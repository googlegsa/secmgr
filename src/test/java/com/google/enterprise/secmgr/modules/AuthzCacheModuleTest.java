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

package com.google.enterprise.secmgr.modules;

import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.testing.AuthorizationTestUtils;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;


/**
 * Unit tests for {@link AuthzCacheModule}.
 */
public class AuthzCacheModuleTest extends SecurityManagerTestCase {
  private static final Resource RESOURCE =
    new Resource("http://blue-sky.com/index.html", null);
  private static final ImmutableList<Resource> RESOURCES = ImmutableList.of(RESOURCE);
  private static final String DOMAIN = "dn";
  private static final String USERNAME = "bobby-drop-tables";

  public void testCacheInitiallyIndeterminate() {
    AuthzCacheModule module = new AuthzCacheModule(6000);
    SessionSnapshot snapshot = makeSessionSnapshot();
    AuthzResult result = authorize(module, snapshot);
    assertEquals(1, result.size());
    String key = result.keySet().iterator().next();
    assertEquals(RESOURCE.getUrl(), key);
    assertEquals(AuthzStatus.INDETERMINATE, result.get(key));
  }

  public void testCacheRemembersPermit() {
    AuthzCacheModule module = new AuthzCacheModule(6000);
    SessionSnapshot snapshot = makeSessionSnapshot();
    module.rememberPermit(RESOURCE.getUrl(), snapshot.getSessionId());
    AuthzResult result = authorize(module, snapshot);
    assertEquals(1, result.size());
    String key = result.keySet().iterator().next();
    assertEquals(RESOURCE.getUrl(), key);
    assertEquals(AuthzStatus.PERMIT, result.get(key));
  }

  public void testCacheRemembersDeny() {
    AuthzCacheModule module = new AuthzCacheModule(6000);
    SessionSnapshot snapshot = makeSessionSnapshot();
    module.rememberDeny(RESOURCE.getUrl(), snapshot.getSessionId());
    AuthzResult result = authorize(module, snapshot);
    assertEquals(1, result.size());
    String key = result.keySet().iterator().next();
    assertEquals(RESOURCE.getUrl(), key);
    assertEquals(AuthzStatus.DENY, result.get(key));
  }

  public void testCacheAcceptsSwitch() {
    AuthzCacheModule module = new AuthzCacheModule(6000);
    SessionSnapshot snapshot = makeSessionSnapshot();
    module.rememberDeny(RESOURCE.getUrl(), snapshot.getSessionId());
    AuthzResult result = authorize(module, snapshot);
    assertEquals(1, result.size());
    String key = result.keySet().iterator().next();
    assertEquals(RESOURCE.getUrl(), key);
    assertEquals(AuthzStatus.DENY, result.get(key));
    module.rememberPermit(RESOURCE.getUrl(), snapshot.getSessionId());
    result = authorize(module, snapshot);
    assertEquals(1, result.size());
    key = result.keySet().iterator().next();
    assertEquals(RESOURCE.getUrl(), key);
    assertEquals(AuthzStatus.PERMIT, result.get(key));
  }

  public void testCacheExpires() throws InterruptedException {
    AuthzCacheModule module = new AuthzCacheModule(1);
    SessionSnapshot snapshot = makeSessionSnapshot();
    module.rememberDeny(RESOURCE.getUrl(), snapshot.getSessionId());

    Thread.sleep(3000);

    AuthzResult result = authorize(module, snapshot);
    assertEquals(1, result.size());
    String key = result.keySet().iterator().next();
    assertEquals(RESOURCE.getUrl(), key);
    assertEquals(AuthzStatus.INDETERMINATE, result.get(key));
  }

  private static SessionSnapshot makeSessionSnapshot() {
    return AuthorizationTestUtils.simpleSnapshot(AuthnPrincipal.make(
        USERNAME, AuthorizationTestUtils.CG, DOMAIN));
  }

  private static AuthzResult authorize(AuthzCacheModule module, SessionSnapshot snapshot) {
    return module.authorize(RESOURCES, snapshot.getView(), AuthorizationTestUtils.DUMMY_RULE);
  }
}
