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

import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.makeQuery;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.simpleSnapshot;

import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.mock.MockAuthorizationMethod;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

import java.util.List;

/**
 * Unit tests for {@link AuthzControllerState}.
 */
public class AuthzControllerStateTest extends SecurityManagerTestCase {
  private static final String FOO = "foo";
  private static final String BAR = "bar";
  private static final String FOOBAR = "foobar";
  private static final String BAZ = "baz";

  private final AuthorizationDispatcher dispatcher;

  public AuthzControllerStateTest() {
    dispatcher = ConfigSingleton.getInstance(AuthorizationDispatcher.class);
  }

  public void testSimple() {
    // create a controller state where each query has one method
    List<AuthorizationQuery> queries
        = ImmutableList.of(
            makeQuery(FOO, makeMethod(FOO)),
            makeQuery(BAR, makeMethod(BAR)),
            makeQuery(FOOBAR, makeMethod(BAR)));
    AuthzControllerState state = AuthzControllerState.makeInitial(queries);
    // all the queries are unfinished
    assertEquals(0, state.countPendingQueries());
    assertEquals(0, countResolvedQueries(state));
    // there are two batches: method FOO and method BAR
    List<AuthzBatch> batches = state.getBatches();
    assertEquals(2, batches.size());
    if (FOO.equals(batches.get(0).getMethod().getName())) {
      assertEquals(BAR, batches.get(1).getMethod().getName());
    } else {
      assertEquals(BAR, batches.get(0).getMethod().getName());
      assertEquals(FOO, batches.get(1).getMethod().getName());
    }
    // iterate: foo and bar will be run
    state = state.next(dispatcher.dispatch(state.getBatches(), simpleSnapshot("bill")));
    assertEquals(0, state.countPendingQueries());
    assertEquals(3, countResolvedQueries(state));
    AuthzResult expected
        = AuthzResult.of(
            FOO, AuthzStatus.PERMIT,
            BAR, AuthzStatus.PERMIT,
            FOOBAR, AuthzStatus.PERMIT);
    AuthzResult actual = state.getResult();
    assertEquals(expected, actual);
  }

  public void testTwoMethods() {
    // create a controller state where each query has the same two methods
    List<AuthorizationQuery> queries
        = ImmutableList.of(
            makeQuery(FOO, makeMethod(FOO), makeMethod(BAR)),
            makeQuery(BAR, makeMethod(FOO), makeMethod(BAR)),
            makeQuery(BAZ, makeMethod(FOO), makeMethod(BAR)));
    AuthzControllerState state = AuthzControllerState.makeInitial(queries);
    // all the queries are unfinished
    assertEquals(3, state.countPendingQueries());
    assertEquals(0, countResolvedQueries(state));
    // there's just one batch: method FOO will be tried first
    List<AuthzBatch> batches = state.getBatches();
    assertEquals(1, batches.size());
    assertEquals(FOO, batches.get(0).getMethod().getName());
    // each unfinished query should only have one remaining method: bar
    for (AuthorizationQuery q : state.getUnfinishedQueries()) {
      assertEquals(1, q.getMethods().size());
      assertEquals(BAR, q.getMethods().get(0).getName());
    }
    // try method foo
    SessionSnapshot snapshot = simpleSnapshot("bill");
    state = state.next(dispatcher.dispatch(state.getBatches(), snapshot));
    assertEquals(0, state.countPendingQueries());
    assertEquals(1, countResolvedQueries(state));
    // should be just one method: bar
    batches = state.getBatches();
    assertEquals(1, batches.size());
    assertEquals(BAR, batches.get(0).getMethod().getName());
    // now try bar
    state = state.next(dispatcher.dispatch(state.getBatches(), snapshot));
    // resource 'bar' is now permitted and 'baz' is permanently indeterminate
    // (because it has no other methods to try)
    assertEquals(0, state.countPendingQueries());
    assertEquals(2, countResolvedQueries(state));
    AuthzResult expected
        = AuthzResult.of(
            FOO, AuthzStatus.PERMIT,
            BAR, AuthzStatus.PERMIT,
            BAZ, AuthzStatus.INDETERMINATE);
    AuthzResult actual = state.getResult();
    assertEquals(expected, actual);
  }

  private static int countResolvedQueries(AuthzControllerState state) {
    int finished = 0;
    for (AuthzStatus status : state.getResult().values()) {
      if (status != AuthzStatus.INDETERMINATE) {
        finished += 1;
      }
    }
    return finished;
  }

  private static AuthorizationMethod makeMethod(String name) {
    return MockAuthorizationMethod.forName(name);
  }
}
