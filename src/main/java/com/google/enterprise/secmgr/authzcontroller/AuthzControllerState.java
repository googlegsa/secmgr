// Copyright 2009 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.secmgr.authzcontroller;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.SetMultimap;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.modules.AuthzResult;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import javax.annotation.concurrent.Immutable;

/**
 * A collection of queries, grouped by method. You create it by giving it a
 * bunch of {@link AuthorizationQuery} objects, each of which has a method
 * queue. The constructor puts all the queries that already have a
 * non-indeterminate status to one side. It also puts all queries that have no
 * methods to one side - they will remain indeterminate, because there's no
 * method to try for them. It then constructs a map of the remaining queries,
 * keyed by the top method on the queue for each, and popping that method off
 * the queue.
 */
@Immutable
public class AuthzControllerState {

  private final ImmutableList<AuthzBatch> batches;
  private final ImmutableList<AuthorizationQuery> unfinishedQueries;
  private final AuthzResult result;

  private AuthzControllerState(ImmutableList<AuthzBatch> batches,
      ImmutableList<AuthorizationQuery> unfinishedQueries,
      AuthzResult result) {
    this.batches = batches;
    this.unfinishedQueries = unfinishedQueries;
    this.result = result;
  }

  /**
   * Make an initial controller state.
   *
   * @param queries The queries to be executed.
   * @return A new controller state containing the given queries.
   */
  public static AuthzControllerState makeInitial(Collection<AuthorizationQuery> queries) {
    return computeNextState(queries, AuthzResult.builder(
        Resource.resourcesToUrls(queriesToResources(queries))).build());
  }

  private static ImmutableList<Resource> queriesToResources(Iterable<AuthorizationQuery> queries) {
    ImmutableList.Builder<Resource> resourcesBuilder = ImmutableList.builder();
    for (AuthorizationQuery query : queries) {
      resourcesBuilder.add(query.getResource());
    }
    return resourcesBuilder.build();
  }

  /**
   * Get the next controller state.
   *
   * @param newResult The result from trying the current batches.
   * @return The next controller state incorporating that result.
   */
  public AuthzControllerState next(AuthzResult newResult) {
    Preconditions.checkNotNull(newResult);
    List<AuthorizationQuery> unresolvedQueries = Lists.newArrayList();
    for (AuthorizationQuery query : unfinishedQueries) {
      if (newResult.get(query.getResource().getUrl()) == AuthzStatus.INDETERMINATE) {
        unresolvedQueries.add(query);
      }
    }
    return computeNextState(unresolvedQueries,
        AuthzResult.builder(result).addAll(newResult).build());
  }

  private static AuthzControllerState computeNextState(Collection<AuthorizationQuery> queries,
      AuthzResult nextResult) {
    SetMultimap<AuthorizationMethod, Resource> map = HashMultimap.create();
    ImmutableList.Builder<AuthorizationQuery> queriesBuilder = ImmutableList.builder();
    for (AuthorizationQuery query : queries) {
      List<? extends AuthorizationMethod> methods = query.getMethods();
      int nMethods = methods.size();
      if (nMethods > 0) {
        map.put(methods.get(0), query.getResource());
        if (nMethods > 1) {
          queriesBuilder.add(query.popMethods());
        }
      }
    }
    ImmutableList.Builder<AuthzBatch> batchesBuilder = ImmutableList.builder();
    for (Map.Entry<AuthorizationMethod, Collection<Resource>> entry : map.asMap().entrySet()) {
      batchesBuilder.add(AuthzBatch.make(entry.getKey(), entry.getValue()));
    }
    return new AuthzControllerState(batchesBuilder.build(), queriesBuilder.build(), nextResult);
  }

  /**
   * @return A final authorization result for all of the finished and unfinished
   * queries.
   */
  public AuthzResult getResult() {
    return result;
  }

  /**
   * @return The number of queries with more methods to try.
   */
  public int countPendingQueries() {
    return unfinishedQueries.size();
  }

  /**
   * @return The batches to be tried in the current iteration.
   */
  public List<AuthzBatch> getBatches() {
    return batches;
  }

  @VisibleForTesting
  Collection<AuthorizationQuery> getUnfinishedQueries() {
    return unfinishedQueries;
  }
}
