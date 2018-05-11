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
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.modules.AuthzCacheModule;
import com.google.enterprise.secmgr.modules.AuthzResult;

import java.io.IOException;
import java.util.Collection;
import java.util.logging.Logger;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * Default implementation of the top-level authorization
 * interface. Depends on an {@link AuthorizationMap} and an
 * {@link AuthorizationDispatcher} which are injected.
 */
@Immutable
@ParametersAreNonnullByDefault
public final class AuthorizationControllerImpl implements AuthorizationController {
  private static final Logger logger
      = Logger.getLogger(AuthorizationControllerImpl.class.getName());

  private final AuthorizationMapManager mapManager;
  private final AuthorizationDispatcher dispatcher;
  private final AuthzCacheModule cacheModule;

  @VisibleForTesting
  @Inject
  AuthorizationControllerImpl(AuthorizationMapManager mapManager,
      AuthorizationDispatcher dispatcher, AuthzCacheModule cacheModule) {
    this.mapManager = mapManager;
    this.dispatcher = dispatcher;
    this.cacheModule = cacheModule;
  }

  @Override
  public AuthzResult authorize(Collection<Resource> resources, SessionSnapshot snapshot,
      boolean enableFastAuthz)
      throws IOException {
    AuthzControllerState state
        = AuthzControllerState.makeInitial(
            mapManager.getAuthorizationMap(enableFastAuthz).mapResources(resources));
    Collection<AuthzBatch> batches = state.getBatches();
    if (batches.isEmpty()) {
      logger.info(snapshot.logMessage("No queries to process"));
    } else {
      int iterations = 0;
      while (true) {
        logger.info(snapshot.logMessage("Iteration: %d; batches: %d; unfinished queries: %d",
                iterations,
                batches.size(),
                state.countPendingQueries()));
        state = state.next(dispatcher.dispatch(batches, snapshot));
        batches = state.getBatches();
        if (batches.isEmpty()) {
          break;
        }
        iterations += 1;
      }
      logger.info(snapshot.logMessage(
          "Authorization done after %d iterations; unfinished queries: %d",
          iterations,
          state.countPendingQueries()));
    }
    AuthzResult results = state.getResult();
    populateUserCache(results, snapshot.getSessionId());
    return results;
  }

  private void populateUserCache(AuthzResult results, String sessionId) {
    for (String resource : results.keySet()) {
      if (!results.wasDeterminedByCache(resource)) {
        switch (results.get(resource)) {
          case PERMIT:
            cacheModule.rememberPermit(resource, sessionId);
            break;
          case DENY:
            cacheModule.rememberDeny(resource, sessionId);
            break;
          case INDETERMINATE:
          default:
            /* NOOP */
        }
      }
    }
  }
}
