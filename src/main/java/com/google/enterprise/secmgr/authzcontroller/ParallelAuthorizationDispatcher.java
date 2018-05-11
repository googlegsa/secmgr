// Copyright 2010 Google Inc.
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

import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.inject.Singleton;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * Parallel implementation of {@link AuthorizationDispatcher}.
 */
@Singleton
@Immutable
public class ParallelAuthorizationDispatcher implements AuthorizationDispatcher {

  private static final Logger logger = 
      Logger.getLogger(ParallelAuthorizationDispatcher.class.getName());
  // default value is 5 seconds, will choose the max of individual authz method
  private static final long TIMEOUT = 5000;  // milliseconds

  @Inject
  private ParallelAuthorizationDispatcher() {
  }

  @Override
  public AuthzResult dispatch(Collection<AuthzBatch> batches, SessionSnapshot snapshot) {

    long timeout = TIMEOUT;

    // reserve a large timeout to complete all batches
    for (AuthzBatch batch : batches) {
      int batchTimeout = batch.getMethod().getTimeout();
      if (batchTimeout > timeout) {
        timeout = batchTimeout;
      }
    }
    timeout += 1000;

    AuthzResult.Builder resultBuilder = AuthzResult.builder();
    try {
      List<AuthzResult> results
          = SecurityManagerUtil.runInParallel(
              makeCallables(batches, snapshot),
              timeout,
              snapshot.getLogDecorator());
      for (AuthzResult result : results) {
        resultBuilder.addAll(result);
      }
    } catch (ExecutionException e) {
      logger.log(Level.WARNING, snapshot.getLogDecorator().apply("Exception in worker thread: "), 
          e.getCause());
    }
    return resultBuilder.build();
  }

  private static List<Callable<AuthzResult>> makeCallables(Collection<AuthzBatch> batches,
      SessionSnapshot snapshot) {
    ImmutableList.Builder<Callable<AuthzResult>> builder = ImmutableList.builder();
    for (AuthzBatch batch : batches) {
      builder.add(new LocalCallable(batch, snapshot));
    }
    return builder.build();
  }

  private static final class LocalCallable implements Callable<AuthzResult> {
    private final AuthzBatch batch;
    private final SessionSnapshot snapshot;

    public LocalCallable(AuthzBatch batch, SessionSnapshot snapshot) {
      this.batch = batch;
      this.snapshot = snapshot;
    }

    @Override
    public AuthzResult call() {
      return batch.getMethod().authorize(batch.getResources(), snapshot);
    }
  }
}
