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

package com.google.enterprise.secmgr.mock;

import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.simpleSnapshot;

import com.google.enterprise.secmgr.authzcontroller.AuthorizationMethod;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.modules.AuthzResult;

import junit.framework.TestCase;

/**
 * Unit tests for {@link MockSamlLikeAuthorizationMethod}.
 */
public class MockSamlLikeAuthorizationMethodTest extends TestCase {

  public void testSimple() {
    AuthzResult expected = AuthzResult.of(
        "http://abc.com/foo/max", AuthzStatus.PERMIT,
        "http://abc.com/foo/saml-indeterminate/max", AuthzStatus.INDETERMINATE,
        "http://abc.com/foo/con", AuthzStatus.DENY);
    AuthorizationMethod method = new MockSamlLikeAuthorizationMethod();
    AuthzResult actual = method.authorize(
        Resource.urlsToResourcesNoAcls(expected.keySet()), simpleSnapshot("max"));
    assertEquals(expected, actual);
  }
}
