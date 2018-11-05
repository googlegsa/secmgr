// Copyright 2011 Google Inc.
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

package com.google.enterprise.secmgr.common;

import com.google.common.collect.Lists;
import java.util.List;
import java.util.concurrent.Callable;
import junit.framework.TestCase;
import org.joda.time.DateTimeUtils;

/** Tests for the generic method of SecurityManagerUtil. */
public class SecurityManagerUtilTest extends TestCase {
  private static final long DELAY_MILLIS = 100;

  /** Creates 5 times as many callables as executor threads and gives them only
      half the time to finish.  Therefore we expect 40% to finish, another 20%
      to be in progress and not finished, and the remaining 40% not to be
      started. */
  public void testTimeoutOnBatchedProcessing() throws Exception {
    int nCallables = 5 * SecurityManagerUtil.getPrimaryThreadPoolSize();
    List<Callable<Integer>> callables = Lists.newArrayList();
    for (int i = 0; i < nCallables; i++) {
      final int result = i;
      callables.add(
          new Callable<Integer>() {
            @Override
            public Integer call()
                throws InterruptedException {
              Thread.sleep(DELAY_MILLIS);
              return result;
            }
          });
    }

    long startMillis = DateTimeUtils.currentTimeMillis();
    List<Integer> answers = SecurityManagerUtil.runInParallel(callables,
        (long) (2.5 * DELAY_MILLIS), SessionUtil.getLogDecorator());
    long endMillis = DateTimeUtils.currentTimeMillis();

    // two things we want to make sure occur:
    // - we get partial results back in cases where we cannot finish all the
    //   work
    assertTrue(answers.size() > 0);
    // - work that went beyond the time limit is timed out
    assertTrue(answers.size() < nCallables);

    long deltaMillis = endMillis - startMillis;
    assertTrue("Timeout was too quick: " + deltaMillis,
        deltaMillis > 2 * DELAY_MILLIS);
  }
}
