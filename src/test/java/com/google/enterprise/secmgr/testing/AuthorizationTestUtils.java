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

package com.google.enterprise.secmgr.testing;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.authzcontroller.AuthorizationMap;
import com.google.enterprise.secmgr.authzcontroller.AuthorizationMethod;
import com.google.enterprise.secmgr.authzcontroller.AuthorizationQuery;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.AuthnMechForm;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.AuthzMechanism;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.modules.AuthzResult;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import junit.framework.TestCase;

/**
 * Utilities for authorization unit tests.
 */
public class AuthorizationTestUtils {

  public static final String STANDARD_PREFIX = "googleconnector://";
  public static final String STANDARD_SUFFIX = ".localhost/";
  public static final String DOCID_SUFFIX = "doc?docid=";
  public static final String UNKNOWN = "unknown";
  public static final String ALLOW_ALL = "allow_all";
  public static final String ALLOW_NONE = "allow_none";
  public static final String ALLOW_BY_SUBSTRING = "allow_by_substring";

  public static final String BAR = "bar";
  public static final String FOO = "foo";
  public static final String XYZZY = "xyzzy";
  public static final String SI_PREFIX = "saml-indeterminate";
  public static final String SI_BAR = SI_PREFIX + "-bar";
  public static final String SI_FOO = SI_PREFIX + "-foo";
  public static final String SI_XYZZY = SI_PREFIX + "-xyzzy";
  public static final String SO_PREFIX = "saml-ok";
  public static final String SO_BAR = SO_PREFIX + "-bar";
  public static final String SO_FOO = SO_PREFIX + "-foo";
  public static final String SO_XYZZY = SO_PREFIX + "-xyzzy";
  public static final String CG = "cg";

  public static final FlexAuthzRule DUMMY_RULE
      = new FlexAuthzRule(FlexAuthzRule.EMPTY_AUTHN_ID, AuthzMechanism.DENY, "",
          FlexAuthzRule.NO_TIME_LIMIT);

  // Don't instantiate.
  private AuthorizationTestUtils() {
    throw new UnsupportedOperationException();
  }

  public static AuthorizationQuery makeQuery(String pattern, AuthorizationMethod... methods) {
    return AuthorizationQuery.make(new Resource(pattern, null), Arrays.asList(methods));
  }

  public static Function<AuthorizationQuery, Resource> getResourceFunc =
      new Function<AuthorizationQuery, Resource>() {
        public Resource apply(AuthorizationQuery q) {
          return q.getResource();
        }
      };

  public static Map.Entry<String, AuthzStatus> makeRule(String pattern, AuthzStatus status) {
    return Maps.immutableEntry(pattern, status);
  }

  public static AuthorizationMap.Builder addStandardAuthorizationRules(
      AuthorizationMap.Builder builder) {
    return builder
        .addRule(standardPattern(ALLOW_ALL), ALLOW_ALL_METHOD)
        .addRule(standardPattern(ALLOW_NONE), ALLOW_NONE_METHOD)
        .addRule(standardPattern(ALLOW_BY_SUBSTRING), ALLOW_BY_SUBSTRING_METHOD);
  }

  public static String standardPattern(String instance) {
    return STANDARD_PREFIX + instance + STANDARD_SUFFIX;
  }

  public static String standardPattern(String instance, String docId) {
    return standardPattern(instance) + DOCID_SUFFIX + docId;
  }

  public static final AuthorizationMethod ALLOW_ALL_METHOD = new AuthorizationMethod() {
      @Override
      public AuthzResult authorize(Collection<Resource> resources, SessionSnapshot snapshot) {
        AuthzResult.Builder builder = AuthzResult.builder();
        for (Resource resource : resources) {
          builder.put(resource.getUrl(), AuthzStatus.PERMIT);
        }
        return builder.build();
      }
      @Override
      public String getName() {
        return ALLOW_ALL;
      }
      @Override
      public int getTimeout() {
        return 0;
      }
      @Override
      public String toString() {
        return "{name:\"" + getName() + "\", class:\"ConnectorAuthorizationMethod\"}";
      }
    };

  public static final AuthorizationMethod ALLOW_NONE_METHOD = new AuthorizationMethod() {
      @Override
      public AuthzResult authorize(Collection<Resource> resources, SessionSnapshot snapshot) {
        AuthzResult.Builder builder = AuthzResult.builder();
        for (Resource resource : resources) {
          builder.put(resource.getUrl(), AuthzStatus.DENY);
        }
        return builder.build();
      }
      @Override
      public String getName() {
        return ALLOW_NONE;
      }
      @Override
      public int getTimeout() {
        return 0;
      }
      @Override
      public String toString() {
        return "{name:\"" + getName() + "\", class:\"ConnectorAuthorizationMethod\"}";
      }
    };

  public static final AuthorizationMethod ALLOW_BY_SUBSTRING_METHOD = new AuthorizationMethod() {
      @Override
      public AuthzResult authorize(Collection<Resource> resources, SessionSnapshot snapshot) {
        String username = snapshot.getView().getUsername();
        AuthzResult.Builder builder = AuthzResult.builder();
        for (Resource resource : resources) {
          builder.put(resource.getUrl(),
              resource.getUrl().contains(username)
              ? AuthzStatus.PERMIT
              : AuthzStatus.DENY);
        }
        return builder.build();
      }
      @Override
      public String getName() {
        return ALLOW_BY_SUBSTRING;
      }
      @Override
      public int getTimeout() {
        return 0;
      }
      @Override
      public String toString() {
        return "{name:\"" + getName() + "\", class:\"ConnectorAuthorizationMethod\"}";
      }
    };

  public static SessionSnapshot simpleSnapshot(String username) {
    return simpleSnapshot(AuthnPrincipal.make(username, CG));
  }

  public static SessionSnapshot simpleSnapshot(Credential... credentials) {
    AuthnMechanism mechanism = AuthnMechForm.make("mech", "http://example.com/");
    AuthnAuthority authority = mechanism.getAuthority();
    return SessionSnapshot.make(
        SecurityManagerConfig.make(
            ImmutableList.of(
                CredentialGroup.builder(CG, "cg", false, false, false)
                .addMechanism(mechanism)
                .build())),
        AuthnSessionState.empty()
        .addCredentials(authority, Arrays.asList(credentials))
        .addVerification(authority,
            Verification.verified(Verification.NEVER_EXPIRES, credentials)));
  }

  public static SessionView simpleView(Credential... credentials) {
    return simpleSnapshot(credentials).getView();
  }

  public static <T extends Comparable<? super T>> void assertComparableCollectionsEqual(
      Collection<T> expected, Collection<T> actual) {
    List<T> sortedExpected = new ArrayList<T>(expected);
    Collections.sort(sortedExpected);
    List<T> sortedActual = new ArrayList<T>(actual);
    Collections.sort(sortedActual);
    TestCase.assertEquals(sortedExpected, sortedActual);
  }
}
