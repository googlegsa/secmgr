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
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.testing.AuthorizationTestUtils;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

import java.io.IOException;
import java.util.List;

/**
 * Unit tests for {@link DenyAuthzModule}.
 */
public class DenyAuthzModuleTest extends SecurityManagerTestCase {

  private static final String BOWL_URL = "http://bowling/strikes-and-gutters";
  private static final String GOLF_URL = "ftp://golfing/birdies-and-bogies";

  public void testSimple()
      throws IOException {
    List<String> urls = ImmutableList.of(BOWL_URL, GOLF_URL);
    AuthzModule module = ConfigSingleton.getInstance(DenyAuthzModule.class);
    AuthzResult result
        = module.authorize(Resource.urlsToResourcesNoAcls(urls),
            AuthorizationTestUtils.simpleView(),
            AuthorizationTestUtils.DUMMY_RULE);
    assertEquals(2, result.size());
    assertEquals(AuthzStatus.DENY, result.get(BOWL_URL));
    assertEquals(AuthzStatus.DENY, result.get(GOLF_URL));
  }
}
