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

import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.ALLOW_ALL_METHOD;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.ALLOW_BY_SUBSTRING_METHOD;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.ALLOW_NONE_METHOD;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.simpleSnapshot;

import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

/**
 * Unit tests for {@link AuthorizationMethodImpl}.
 */
public class AuthorizationMethodImplTest extends SecurityManagerTestCase {

  private static String makeUrl(String connectorName, String docId) {
    return "googleconnector://" + connectorName + ".localhost/doc?docid=" + docId;
  }

  private static final String URL1 = makeUrl("allow_all", "bar");
  private static final String URL2 = makeUrl("allow_all", "foo");
  private static final String URL3 = makeUrl("allow_all", "xyzzy");
  private static final String URL4 = makeUrl("allow_none", "bar");
  private static final String URL5 = makeUrl("allow_none", "foo");
  private static final String URL6 = makeUrl("allow_none", "xyzzy");
  private static final String URL7 = makeUrl("allow_by_substring", "bar");
  private static final String URL8 = makeUrl("allow_by_substring", "foo");
  private static final String URL9 = makeUrl("allow_by_substring", "xyzzy");

  public void testAllowAll() {
    AuthzResult expected
        = AuthzResult.of(
            URL1, AuthzStatus.PERMIT,
            URL2, AuthzStatus.PERMIT,
            URL3, AuthzStatus.PERMIT);
    AuthzResult actual = ALLOW_ALL_METHOD.authorize(
        Resource.urlsToResourcesNoAcls(expected.keySet()), simpleSnapshot("max"));
    assertEquals(expected, actual);
  }

  public void testAllowNone() {
    AuthzResult expected
        = AuthzResult.of(
            URL4, AuthzStatus.DENY,
            URL5, AuthzStatus.DENY,
            URL6, AuthzStatus.DENY);
    AuthzResult actual = ALLOW_NONE_METHOD.authorize(
        Resource.urlsToResourcesNoAcls(expected.keySet()), simpleSnapshot("max"));
    assertEquals(expected, actual);
  }

  public void testAllowBySubstring() {
    AuthzResult expected
        = AuthzResult.of(
            URL7, AuthzStatus.PERMIT,
            URL8, AuthzStatus.DENY,
            URL9, AuthzStatus.DENY);
    AuthzResult actual = ALLOW_BY_SUBSTRING_METHOD.authorize(
        Resource.urlsToResourcesNoAcls(expected.keySet()), simpleSnapshot("bar"));
    assertEquals(expected, actual);
  }
}
