// Copyright 2010 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.secmgr.modules;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.enterprise.ldap.LDAPConfig;
import com.google.enterprise.ldap.LDAPConstants.AuthMethod;
import com.google.enterprise.ldap.LDAPConstants.GroupResolutionFormat;
import com.google.enterprise.ldap.LDAPConstants.SSLSupport;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.config.AuthnMechLdap;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.GroupMemberships;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.enterprise.secmgr.mock.MockLDAPClient;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.util.Set;

/**
 * LdapModule unit test.
 */
public class LdapModuleTest extends SecurityManagerTestCase {

  private static final String CG_NAME = "ADG1";
  private static final String USER1 = "foo";
  private static final String PASS1 = "foo";
  private static final String USER2 = "bar";
  private static final String PASS2 = "baz";
  private static final String USER3 = "user3";
  private static final String PASS3 = "pass3";
  private static final String USER4 = "user4";
  private static final String PASS4 = "pass4";
  private static final String DOMAIN = "esodomain.com";
  private static final String GROUP2 = "groupbar";
  private static final String GROUP3 = "Everyone";
  private static final String AD_GROUP1 =
              "CN=Domain Users,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com";
  private static final String AD_GROUP2 =
               "CN=Schema Admins,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com";
  private static final String AD_GROUP3 =
               "CN=Domain Admins,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com";
  private static final ImmutableSet<Group> GROUPS2 =
      ImmutableSet.of(Group.make(GROUP2, CG_NAME, DOMAIN));
  private static final ImmutableSet<Group> GROUPS3 =
      ImmutableSet.of(Group.make(GROUP2, CG_NAME, DOMAIN), Group.make(GROUP3, CG_NAME));
  private static final String NETBIOSNAME = "NETBIOSNAME";
  private static final String REWRITE_TO_NETBIOSNAME = "REWRITE_TO_" + NETBIOSNAME;

  private static final ImmutableSet<Group> GROUPS4 =
      ImmutableSet.of(
          Group.make(AD_GROUP1, CG_NAME),
          Group.make(AD_GROUP2, CG_NAME),
          Group.make(AD_GROUP3, CG_NAME));
  private final TestState defaultState;
  private final LdapModule module;
  private final MockLDAPClient mockLdapClient;

  private static class TestState {
    final AuthnMechLdap mech;
    //final AuthnMechanism mech;
    final SecurityManagerConfig config;
    AuthnSession session = null;

    TestState(String mechName, boolean enableGroupLookup, boolean enableImplicitEveryone,
              int timeout) {
      mech = AuthnMechLdap.make(mechName, "hostport", "binddn", "pw", "searchbase", "userfilter",
          "groupfilter", GroupResolutionFormat.CN.toString(), SSLSupport.NO_SSL.getSslType(),
          AuthMethod.SIMPLE.getInt(), true, enableGroupLookup, enableImplicitEveryone, timeout,
          AuthnMechLdap.getDefaultTrustDuration());
      config = makeConfig(ImmutableList.of(CredentialGroup
          .builder(CG_NAME, CG_NAME + " display", true, true, false).addMechanism(mech).build()));
    }

    TestState(String mechName, boolean enableGroupLookup, boolean enableImplicitEveryone) {
      this(mechName, enableGroupLookup, enableImplicitEveryone, AuthnMechanism.NO_TIME_LIMIT);
    }

    void resetSession() {
      session = AuthnSession.getInstance(config);
    }

    void addCredentials(String username, String password) {
      session.addCredentials(mech, AuthnPrincipal.make(username, CG_NAME), 
          CredPassword.make(password));
    }

    void resetSessionWithUsernameDomain(String username, String domain) {
      resetSession();
      Credential credential = AuthnPrincipal.make(username, CG_NAME, domain);
      session.addCredentials(mech, credential);
      session.addVerification(mech.getAuthority(),
          Verification.verified(Verification.NEVER_EXPIRES, credential));

    }
    void resetSessionWithCredentials(String username, String password) {
      resetSession();
      addCredentials(username, password);
    }

    AuthnMechLdap getMech() {
      return mech;
    }
  }

  public LdapModuleTest() {
    defaultState = new TestState("mech1", true, false);
    Set<String> groups = ImmutableSet.of(GROUP2);
    Set<String> adGroups = ImmutableSet.of(AD_GROUP1, AD_GROUP2, AD_GROUP3);
    mockLdapClient = new MockLDAPClient(new LDAPConfig());
    mockLdapClient.setUserDb(ImmutableMap.of(
        USER1, PASS1, USER2, PASS2, USER3, PASS3, USER4, PASS4));
    mockLdapClient.setGroupsDb(ImmutableMap.of(USER2, groups, USER3, groups, USER4, adGroups));
    module = new LdapModule(mockLdapClient);
  }

  @Override
  public void setUp() {
    defaultState.resetSession();
  }

  public void testGood1() {
    addCredentials(USER1, PASS1);
    assertEquals(VerificationStatus.VERIFIED, authenticate());
    assertVerification(VerificationStatus.VERIFIED, AuthnPrincipal.make(USER1, CG_NAME, DOMAIN),
        CredPassword.make(PASS1));
  }

  public void testGood2() {
    addCredentials(USER2, PASS2);
    assertEquals(VerificationStatus.VERIFIED, authenticate());
    assertVerification(VerificationStatus.VERIFIED, AuthnPrincipal.make(USER2, CG_NAME, DOMAIN),
        CredPassword.make(PASS2), GroupMemberships.make(GROUPS2));
  }

  public void testGood3() {
    mockLdapClient.setGroupResolutionFormat(GroupResolutionFormat.DN);
    addCredentials(USER4, PASS4);
    assertEquals(VerificationStatus.VERIFIED, authenticate());
    assertVerification(VerificationStatus.VERIFIED, AuthnPrincipal.make(USER4, CG_NAME, DOMAIN),
        CredPassword.make(PASS4), GroupMemberships.make(GROUPS4));
  }

  public void testBad1() {
    addCredentials(USER1, PASS2);
    assertEquals(VerificationStatus.REFUTED, authenticate());
    assertVerification(VerificationStatus.REFUTED, AuthnPrincipal.make(USER1, CG_NAME),
        CredPassword.make(PASS2));
  }

  public void testBad2() {
    addCredentials(USER2, PASS1);
    assertEquals(VerificationStatus.REFUTED, authenticate());
    assertVerification(VerificationStatus.REFUTED, AuthnPrincipal.make(USER2, CG_NAME),
        CredPassword.make(PASS1));
  }

  public void testImplicitEveryone() {
    TestState state;
    state = new TestState("LookupGroupsEnabled_ImplEveryoneEnabled", true, true);
    state.resetSessionWithCredentials(USER3, PASS3);
    assertEquals(VerificationStatus.VERIFIED, authenticate(state));
    assertVerification(state, VerificationStatus.VERIFIED,
        AuthnPrincipal.make(USER3, CG_NAME, DOMAIN), CredPassword.make(PASS3),
        GroupMemberships.make(GROUPS3));

    state = new TestState("LookupGroupsDisabled_ImplEveryoneEnabled", false, true);
    state.resetSessionWithCredentials(USER3, PASS3);
    assertEquals(VerificationStatus.VERIFIED, authenticate(state));
    assertVerification(state, VerificationStatus.VERIFIED,
        AuthnPrincipal.make(USER3, CG_NAME, DOMAIN), CredPassword.make(PASS3),
        GroupMemberships.make(ImmutableSet.of(Group.make("Everyone", CG_NAME))));
  }

  public void testTimeout() {
    TestState state;
    state = new TestState("NonDefaultTimeout", false, false, 2000);
    assertEquals(2000, state.getMech().getTimeout());
    LdapModule module = new LdapModule();
    assertEquals(2000, module.getLDAPClient(state.getMech()).timeout());
  }

  public void testRewriteDomain() {
    TestState state;
    state = new TestState("DomainRewrite", false, false);
    state.resetSessionWithUsernameDomain(USER1, REWRITE_TO_NETBIOSNAME);
    assertEquals(VerificationStatus.VERIFIED, authenticate(state));
    assertVerification(
        state, VerificationStatus.VERIFIED, AuthnPrincipal.make(USER1, CG_NAME, NETBIOSNAME));
  }

  private void addCredentials(String username, String password) {
    defaultState.addCredentials(username, password);
  }

  private VerificationStatus authenticate() {
    return authenticate(defaultState);
  }

  private VerificationStatus authenticate(TestState state) {
    return AuthnController.invokeModule(module, state.session.getView(state.mech), state.session);
  }

  private void assertVerification(TestState state,
      VerificationStatus expectedStatus, Credential... expectedCredentials) {
    Set<Verification> verifications =
        ImmutableSet.copyOf(state.session.getView(state.mech).getVerifications());
    assertEquals(1, verifications.size());
    Verification verification = Iterables.get(verifications, 0);
    assertEquals(expectedStatus, verification.getStatus());
    assertEquals(ImmutableSet.copyOf(expectedCredentials), verification.getCredentials());
  }

  private void assertVerification(VerificationStatus expectedStatus,
      Credential... expectedCredentials) {
    assertVerification(defaultState, expectedStatus, expectedCredentials);
  }
}
