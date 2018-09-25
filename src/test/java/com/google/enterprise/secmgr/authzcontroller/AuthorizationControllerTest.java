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

import static com.google.enterprise.secmgr.common.AuthzStatus.DENY;
import static com.google.enterprise.secmgr.common.AuthzStatus.INDETERMINATE;
import static com.google.enterprise.secmgr.common.AuthzStatus.PERMIT;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.ALLOW_ALL;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.ALLOW_BY_SUBSTRING;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.ALLOW_NONE;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.BAR;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.FOO;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SI_BAR;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SI_FOO;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SI_XYZZY;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SO_BAR;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SO_FOO;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SO_PREFIX;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SO_XYZZY;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.UNKNOWN;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.XYZZY;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.addStandardAuthorizationRules;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.makeRule;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.simpleSnapshot;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.standardPattern;

import com.google.common.base.Preconditions;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.mock.MockSamlLikeAuthorizationMethod;
import com.google.enterprise.secmgr.modules.AuthzCacheModule;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

import java.io.IOException;
import java.util.Set;

/**
 * Unit tests for {@link AuthorizationController}.
 */
public class AuthorizationControllerTest extends SecurityManagerTestCase {

  /**
   * Each result is dispatched to its connector, except for the last which
   * doesn't have a registered connector.  No other method matches, so it is
   * indeterminate.
   */
  public void testDisjointRules()
      throws IOException {
    AuthorizationMap.Builder builder = AuthorizationMap.builder();
    addStandardAuthorizationRules(builder);
    tryQuery(builder.build(), DISJOINT_CONNECTORS_RESULTS);
  }

  private static final AuthzResult DISJOINT_CONNECTORS_RESULTS = AuthzResult.builder()
      .add(makeRule(standardPattern(ALLOW_ALL, BAR), PERMIT))
      .add(makeRule(standardPattern(ALLOW_ALL, FOO), PERMIT))
      .add(makeRule(standardPattern(ALLOW_ALL, XYZZY), PERMIT))
      .add(makeRule(standardPattern(ALLOW_NONE, BAR), DENY))
      .add(makeRule(standardPattern(ALLOW_NONE, FOO), DENY))
      .add(makeRule(standardPattern(ALLOW_NONE, XYZZY), DENY))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, FOO), PERMIT))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, BAR), DENY))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, XYZZY), DENY))
      .add(makeRule(standardPattern(UNKNOWN, XYZZY), INDETERMINATE))
      .build();

  /**
   * In this test, the mock-saml will be called first for all urls.  It will
   * return indeterminate for the ones that contain "saml-indeterminate".  Those
   * will then be authorized by the connectors named in their urls - so their
   * decisions are the same as the ones in the disjoint test above.  The
   * remainder are decided by mock-saml, which simply returns PERMIT or DENY
   * based on whether they contain "saml-ok".  These decisions are different
   * from what would have been decided by the connector methods.  The last url
   * has no registered connector, but is allowed by mock-saml.
   */
  public void testOverlappingRulesSamlFirst()
      throws IOException {
    AuthorizationMap.Builder builder = AuthorizationMap.builder();
    builder.addRule("/", new MockSamlLikeAuthorizationMethod(SO_PREFIX));
    addStandardAuthorizationRules(builder);
    tryQuery(builder.build(), OVERLAPPING_RULES_SAML_FIRST_RESULTS);
  }

  private static final AuthzResult OVERLAPPING_RULES_SAML_FIRST_RESULTS = AuthzResult.builder()
      .add(makeRule(standardPattern(ALLOW_ALL, SI_BAR), PERMIT))
      .add(makeRule(standardPattern(ALLOW_ALL, SI_FOO), PERMIT))
      .add(makeRule(standardPattern(ALLOW_ALL, SI_XYZZY), PERMIT))
      .add(makeRule(standardPattern(ALLOW_NONE, SI_BAR), DENY))
      .add(makeRule(standardPattern(ALLOW_NONE, SI_FOO), DENY))
      .add(makeRule(standardPattern(ALLOW_NONE, SI_XYZZY), DENY))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, SI_FOO), PERMIT))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, SI_BAR), DENY))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, SI_XYZZY), DENY))
      .add(makeRule(standardPattern(ALLOW_ALL, BAR), DENY))
      .add(makeRule(standardPattern(ALLOW_ALL, FOO), DENY))
      .add(makeRule(standardPattern(ALLOW_ALL, XYZZY), DENY))
      .add(makeRule(standardPattern(ALLOW_NONE, SO_BAR), PERMIT))
      .add(makeRule(standardPattern(ALLOW_NONE, SO_FOO), PERMIT))
      .add(makeRule(standardPattern(ALLOW_NONE, SO_XYZZY), PERMIT))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, FOO), DENY))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, SO_BAR), PERMIT))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, SO_XYZZY), PERMIT))
      .add(makeRule(standardPattern(UNKNOWN, SO_XYZZY), PERMIT))
      .build();

  public void testOverlappingRulesSamlLast()
      throws IOException {
    AuthorizationMap.Builder builder = AuthorizationMap.builder();
    addStandardAuthorizationRules(builder);
    builder.addRule("/", new MockSamlLikeAuthorizationMethod(SO_PREFIX));
    tryQuery(builder.build(), OVERLAPPING_RULES_SAML_LAST_RESULTS);
  }

  private static final AuthzResult OVERLAPPING_RULES_SAML_LAST_RESULTS = AuthzResult.builder()
      .add(makeRule(standardPattern(ALLOW_ALL, SI_BAR), PERMIT))
      .add(makeRule(standardPattern(ALLOW_ALL, SI_FOO), PERMIT))
      .add(makeRule(standardPattern(ALLOW_ALL, SI_XYZZY), PERMIT))
      .add(makeRule(standardPattern(ALLOW_NONE, SI_BAR), DENY))
      .add(makeRule(standardPattern(ALLOW_NONE, SI_FOO), DENY))
      .add(makeRule(standardPattern(ALLOW_NONE, SI_XYZZY), DENY))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, SI_FOO), PERMIT))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, SI_BAR), DENY))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, SI_XYZZY), DENY))
      .add(makeRule(standardPattern(ALLOW_ALL, BAR), PERMIT))
      .add(makeRule(standardPattern(ALLOW_ALL, FOO), PERMIT))
      .add(makeRule(standardPattern(ALLOW_ALL, XYZZY), PERMIT))
      .add(makeRule(standardPattern(ALLOW_NONE, SO_BAR), DENY))
      .add(makeRule(standardPattern(ALLOW_NONE, SO_FOO), DENY))
      .add(makeRule(standardPattern(ALLOW_NONE, SO_XYZZY), DENY))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, FOO), PERMIT))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, SO_BAR), DENY))
      .add(makeRule(standardPattern(ALLOW_BY_SUBSTRING, SO_XYZZY), DENY))
      .add(makeRule(standardPattern(UNKNOWN, SO_XYZZY), PERMIT))
      .build();

  private void tryQuery(AuthorizationMap map, AuthzResult expected)
      throws IOException {
    Set<String> resourceUrls = expected.keySet();
    AuthorizationController controller = makeController(map);
    AuthzResult actual = controller.authorize(
        Resource.urlsToResourcesNoAcls(resourceUrls), simpleSnapshot(FOO), false);
    assertEquals(expected, actual);
  }

  private static AuthorizationController makeController(AuthorizationMap map) {
    return new AuthorizationControllerImpl(
        new MockAuthorizationMapManager(map),
        ConfigSingleton.getInstance(AuthorizationDispatcher.class),
        ConfigSingleton.getInstance(AuthzCacheModule.class));
  }

  private static final class MockAuthorizationMapManager implements AuthorizationMapManager {
    private final AuthorizationMap map;

    MockAuthorizationMapManager(AuthorizationMap map) {
      Preconditions.checkNotNull(map);
      this.map = map;
    }

    @Override
    public AuthorizationMap getAuthorizationMap(boolean fastAuthz) {
      return map;
    }
  }
}
