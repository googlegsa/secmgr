// Copyright 2018 Google Inc.
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

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.io.Files;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.MemberToGroupsResolverMap;
import com.google.enterprise.secmgr.common.MemberToGroupsResolverMapProvider;
import com.google.enterprise.secmgr.config.AuthnMechGroups;
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
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.enterprise.supergsa.security.AclPrincipal;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.mockito.Mockito;

/**
 * Unit tests for {@link GroupsUpdateModule}.
 */
public class GroupsUpdateModuleTest extends SecurityManagerTestCase {

  private static final String USER1 = "user1";
  private static final String USER2 = "user2";
  private static final String USER3 = "user3";
  private static final String USER4 = "user4";
  private static final String USER5 = "user5";
  private static final String CG_NAME1 = "CG1";
  private static final String CG_NAME2 = "CG2";
  private static final String CG_NAME3 = "CG3";
  private static final String CG_NAME4 = "CG4";
  private static final String CG_NAME5 = "CG5";
  private static final String AD_NAME1 = "AD1";
  private static final String AD_NAME2 = "AD2";
  private static final String AD_NAME3 = "AD3";
  private static final String AD_NAME4 = "AD4";
  private static final String AD_NAME5 = "AD5";

  private static final String GROUP1 = "Group1";
  private static final String GROUP2 = "Group2";
  private static final String GROUP3 = "Group3";
  private static final String SUBGROUP1 = "subGroup1";
  private static final String SUBSUBGROUP1 = "subsubGroup1";
  private static final String NAMESPACE1 = "Default";
  private static final String NAMESPACE2 = "NS";
  private static final String NAMESPACE3 = "Default";
  private static final String NAMESPACE4 = "Default";
  private static final String NAMESPACE5 = "Default";
  private static final String DOMAIN1 = "domain1.com";
  private static final String DOMAIN2 = "domain2.com";
  private static final String DOMAIN3 = "domain3.com";
  private static final String DOMAIN4 = "domain4.com";
  private static final String DOMAIN5 = "domain5.com";

  private static final String NEWGROUP1 = "NewGroup1";
  private static final String NEWGROUP2 = "NewGroup2";
  private static final String NEWGROUP3 = "NewGroup3";
  private static final String NEWGROUP4 = "NewGroup4";
  private static final String NEWNAMESPACE1 = "NewNS1";
  private static final String NEWNAMESPACE2 = "NewNS2";
  private static final String NEWNAMESPACE3 = "NewNS3";
  private static final String NEWNAMESPACE4 = "NewNS4";
  private static final String NEWDOMAIN1 = "new_domain1.com";
  private static final String NEWDOMAIN2 = "new_domain2.com";
  private static final String NEWDOMAIN3 = "new_domain3.com";
  private static final String NEWDOMAIN4 = "new_domain4.com";

  private static final long FILE_RELOAD_INTERVAL_MILLIS = 20;
  private static final long FILE_TIMESTAMP_PRECISION_MILLIS = 1000;
  private static final long WAIT_FOR_MAP_REGENERATE = 1000;

  private static final String GROUPSFILENAME = FileUtil.getContextDirectory()
      + "/" + "groups_update.enterprise";
  private static final String GROUPSFEEDFILENAME = FileUtil.getContextDirectory()
      + "/" + "groups_update_feed.enterprise";
  private static final String GROUPSFILENAME2 = FileUtil.getContextDirectory()
      + "/" + "groups_update2.enterprise";
  private static final String GROUPSFEEDFILENAME2 = FileUtil.getContextDirectory()
      + "/" + "groups_update_feed2.enterprise";

  // In groups_update.enterprise, GROUP1 has members of USER1, SUBGROUP1, USER4, SUBGROUP1 has
  // members of SUBSUBGROUP1, SUBSUBGROUP1 has members of USER3, USER4. GROUP2 has member of USER1,
  // USER2. In groups_update_feed.enterprise, GROUP1 has members of USER1, USER5, SUBGROUP1,
  // SUBGROUP1 has members of USER2, USER3. GROUP3 has members of USER4, USER5.
  private static final ImmutableSet<Group> USER1_GROUPS =
      ImmutableSet.<Group>of(
          Group.make(GROUP1, NAMESPACE1, DOMAIN1), Group.make(GROUP2, NAMESPACE2, DOMAIN2));
  private static final ImmutableSet<Group> USER2_GROUPS =
      ImmutableSet.<Group>of(
          Group.make(GROUP1, NAMESPACE1, DOMAIN1),
          Group.make(SUBGROUP1, NAMESPACE3, DOMAIN3),
          Group.make(GROUP2, NAMESPACE2, DOMAIN2));
  private static final ImmutableSet<Group> USER3_GROUPS =
      ImmutableSet.<Group>of(
          Group.make(GROUP1, NAMESPACE1, DOMAIN1),
          Group.make(SUBGROUP1, NAMESPACE3, DOMAIN3),
          Group.make(SUBSUBGROUP1, NAMESPACE4, DOMAIN4));
  private static final ImmutableSet<Group> USER4_GROUPS =
      ImmutableSet.<Group>of(
          Group.make(GROUP1, NAMESPACE1, DOMAIN1),
          Group.make(SUBGROUP1, NAMESPACE3, DOMAIN3),
          Group.make(SUBSUBGROUP1, NAMESPACE4, DOMAIN4),
          Group.make(GROUP3, NAMESPACE5, DOMAIN5));
  private static final ImmutableSet<Group> USER5_GROUPS =
      ImmutableSet.<Group>of(
          Group.make(GROUP1, NAMESPACE1, DOMAIN1), Group.make(GROUP3, NAMESPACE5, DOMAIN5));
  private static final ImmutableSet<Group> USER5_GROUPS_WITH_EXIST_GROUPS =
      ImmutableSet.<Group>of(
          Group.make(GROUP1, NAMESPACE1, DOMAIN1),
          Group.make(SUBGROUP1, NAMESPACE3, DOMAIN3),
          Group.make(SUBSUBGROUP1, NAMESPACE4, DOMAIN4),
          Group.make(GROUP3, NAMESPACE5, DOMAIN5));

  // In groups_update2.enterprise, NEWGROUP1 has members of USER1, USER2, NEWGROUP2 has members of
  // USER2.
  private static final ImmutableSet<Group> USER1_GROUPS2 =
      ImmutableSet.<Group>of(
          Group.make(NEWGROUP1, NEWNAMESPACE1, NEWDOMAIN1),
          Group.make(GROUP1, NAMESPACE1, DOMAIN1));
  private static final ImmutableSet<Group> USER2_GROUPS2 =
      ImmutableSet.<Group>of(
          Group.make(NEWGROUP1, NEWNAMESPACE1, NEWDOMAIN1),
          Group.make(NEWGROUP2, NEWNAMESPACE2, NEWDOMAIN2),
          Group.make(GROUP1, NAMESPACE1, DOMAIN1),
          Group.make(SUBGROUP1, NAMESPACE3, DOMAIN3));
  private static final ImmutableSet<Group> USER3_GROUPS2 =
      ImmutableSet.<Group>of(
          Group.make(GROUP1, NAMESPACE1, DOMAIN1), Group.make(SUBGROUP1, NAMESPACE3, DOMAIN3));
  private static final ImmutableSet<Group> USER4_GROUPS2 =
      ImmutableSet.<Group>of(Group.make(GROUP3, NAMESPACE5, DOMAIN5));
  private static final ImmutableSet<Group> USER5_GROUPS2 =
      ImmutableSet.<Group>of(
          Group.make(GROUP1, NAMESPACE1, DOMAIN1), Group.make(GROUP3, NAMESPACE5, DOMAIN5));

  // In groups_update2_feed.enterprise, NEWGROUP3 has members of USER2, USER3, USER5, NEWGROUP4 has
  // members of USER3, USER4.
  private static final ImmutableSet<Group> USER1_GROUPS3 =
      ImmutableSet.<Group>of(Group.make(NEWGROUP1, NEWNAMESPACE1, NEWDOMAIN1));
  private static final ImmutableSet<Group> USER2_GROUPS3 =
      ImmutableSet.<Group>of(
          Group.make(NEWGROUP1, NEWNAMESPACE1, NEWDOMAIN1),
          Group.make(NEWGROUP2, NEWNAMESPACE2, NEWDOMAIN2),
          Group.make(NEWGROUP3, NEWNAMESPACE3, NEWDOMAIN3));
  private static final ImmutableSet<Group> USER3_GROUPS3 =
      ImmutableSet.<Group>of(
          Group.make(NEWGROUP3, NEWNAMESPACE3, NEWDOMAIN3),
          Group.make(NEWGROUP4, NEWNAMESPACE4, NEWDOMAIN4));
  private static final ImmutableSet<Group> USER4_GROUPS3 =
      ImmutableSet.<Group>of(Group.make(NEWGROUP4, NEWNAMESPACE4, NEWDOMAIN4));
  private static final ImmutableSet<Group> USER5_GROUPS3 =
      ImmutableSet.<Group>of(Group.make(NEWGROUP3, NEWNAMESPACE3, NEWDOMAIN3));

  private static final AuthnMechGroups MECH1 = AuthnMechGroups.make(
      "MECH1", AuthnMechanism.NO_TIME_LIMIT, AuthnMechGroups.getDefaultTrustDuration());
  private static final AuthnMechGroups MECH2 = AuthnMechGroups.make(
      "MECH2", AuthnMechanism.NO_TIME_LIMIT, AuthnMechGroups.getDefaultTrustDuration());
  private static final AuthnMechGroups MECH3 = AuthnMechGroups.make(
      "MECH3", AuthnMechanism.NO_TIME_LIMIT, AuthnMechGroups.getDefaultTrustDuration());
  private static final AuthnMechGroups MECH4 = AuthnMechGroups.make(
      "MECH4", AuthnMechanism.NO_TIME_LIMIT, AuthnMechGroups.getDefaultTrustDuration());
  private static final AuthnMechGroups MECH5 = AuthnMechGroups.make(
      "MECH5", AuthnMechanism.NO_TIME_LIMIT, AuthnMechGroups.getDefaultTrustDuration());

  private static final CredentialGroup CG1 =
      CredentialGroup.builder(CG_NAME1, CG_NAME1 + " display", true, true, false)
          .addMechanism(MECH1)
          .build();
  private static final CredentialGroup CG2 =
      CredentialGroup.builder(CG_NAME2, CG_NAME2 + " display", true, true, false)
          .addMechanism(MECH2)
          .build();
  private static final CredentialGroup CG3 =
      CredentialGroup.builder(CG_NAME3, CG_NAME3 + " display", true, true, false)
          .addMechanism(MECH3)
          .build();
  private static final CredentialGroup CG4 =
      CredentialGroup.builder(CG_NAME4, CG_NAME4 + " display", true, true, false)
          .addMechanism(MECH4)
          .build();
  private static final CredentialGroup CG5 =
      CredentialGroup.builder(CG_NAME5, CG_NAME5 + " display", true, true, false)
          .addMechanism(MECH5)
          .build();

  private final TestState defaultState;
  private ScheduledExecutorService testExecutor;

  private static class TestState {
    private final ImmutableList<CredentialGroup> credentialGroups;
    private final SecurityManagerConfig config;
    private AuthnSession session = null;

    public TestState(CredentialGroup... cgs) {
      credentialGroups = ImmutableList.copyOf(cgs);
      config = makeConfig(credentialGroups);
    }

    public void resetSession() {
      session = AuthnSession.newInstance(config);
    }

    public void addVerification(String cgName, String username, String cg, String ad) {
      AuthnMechanism groupsMech = getGroupsMechForCGName(cgName);
      if (groupsMech == null) {
        return;
      }
      Credential credential = AuthnPrincipal.make(username, cg, ad);
      // This is just for test purpose.
      session.addVerification(groupsMech.getAuthority(),
          Verification.verified(Verification.NEVER_EXPIRES, credential));
    }

    public void addUnverifiedCredential(String cgName, String username, String cg, String ad) {
      AuthnMechanism groupsMech = getGroupsMechForCGName(cgName);
      session.addCredentials(groupsMech, AuthnPrincipal.make(username, cg, ad), 
         CredPassword.make(""));
    }

    public void addVerificationWithGroups(String cgName, Credential user, Set<Group> groups) {
      AuthnMechanism groupsMech = getGroupsMechForCGName(cgName);
      if (groupsMech == null) {
        return;
      }
      ImmutableSet.Builder<Credential> builder = ImmutableSet.builder();
      builder.add(user);
      builder.add(session.getView(groupsMech).extendGroupMemberships(groups));
      session.addVerification(groupsMech.getAuthority(),
          Verification.verified(Verification.NEVER_EXPIRES, builder.build()));
    }

    public AuthnMechanism getGroupsMechForCGName(String cgName) {
      for (CredentialGroup cg : credentialGroups) {
        if (cg.getName().equals(cgName)) {
          return cg.getFirstMechanismOfType(AuthnMechGroups.class);
        }
      }
      return null;
    }
  }

  public GroupsUpdateModuleTest() {
    defaultState = new TestState(CG1, CG2, CG3, CG4, CG5);
  }

  @Override
  public void setUp() {
    testExecutor = new TestScheduledExecutorService();
    defaultState.resetSession();
  }

  public void testUnverifiedUser1() {
    GroupsUpdateModule module = new GroupsUpdateModule(FILE_RELOAD_INTERVAL_MILLIS,
        new String[] { GROUPSFILENAME, GROUPSFEEDFILENAME }, Optional.of(testExecutor));
    addUnverifiedCredential(CG_NAME1, USER1, CG_NAME1, AD_NAME1);

    authenticate(module, CG_NAME1);
    Set<Verification> verifications = defaultState.session
        .getView(defaultState.getGroupsMechForCGName(CG_NAME1))
        .getVerifications();
    assertThat(verifications.size()).isEqualTo(0);
    Set<Group> groups = defaultState.session
        .getView(defaultState.getGroupsMechForCGName(CG_NAME1))
        .getVerifiedGroups();
    assertThat(groups.size()).isEqualTo(0);
  }
 
  @SuppressWarnings("unchecked")
  public void testLookupGroupsShouldSkipNullMemberToGroupsResolvers() throws Exception {
    GroupsUpdateModule module = new GroupsUpdateModule(FILE_RELOAD_INTERVAL_MILLIS,
        new String[] { GROUPSFILENAME, GROUPSFEEDFILENAME }, Optional.of(testExecutor));
    ImmutableSet<AclPrincipal> members = ImmutableSet.of(AclPrincipal.getDefaultInstance());
    ImmutableSet.Builder<Group> groupBuilder = Mockito.mock(ImmutableSet.Builder.class);
    
    MemberToGroupsResolverMapProvider mockProvider = Mockito.mock(
        MemberToGroupsResolverMapProvider.class);
    when(mockProvider.getResolver()).thenReturn(null);
    setFinalField(module, "groupDefs", Arrays.asList(mockProvider));
    
    module.lookupGroups(members, groupBuilder);
    verify(groupBuilder, never()).add(any(Group.class));
  }

  // Tests User1 is in multiple groups and in both groups files.
  public void testUser1() {
    GroupsUpdateModule module = new GroupsUpdateModule(FILE_RELOAD_INTERVAL_MILLIS,
        new String[] { GROUPSFILENAME, GROUPSFEEDFILENAME }, Optional.of(testExecutor));
    addVerification(CG_NAME1, USER1, CG_NAME1, AD_NAME1);

    assertThat(authenticate(module, CG_NAME1)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME1, GroupMemberships.make(USER1_GROUPS));
  }

  // Tests User2 is in multiple groups, nested groups and in both groups files.
  public void testUser2() {
    GroupsUpdateModule module = new GroupsUpdateModule(FILE_RELOAD_INTERVAL_MILLIS,
        new String[] { GROUPSFILENAME, GROUPSFEEDFILENAME }, Optional.of(testExecutor));
    addVerification(CG_NAME2, USER2, CG_NAME2, AD_NAME2);

    assertThat(authenticate(module, CG_NAME2)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME2, GroupMemberships.make(USER2_GROUPS));
  }

  // Tests User3 is in nested groups and both group files.
  @SuppressWarnings("unused")
  public void testUser3() throws IOException {
    GroupsUpdateModule module = new GroupsUpdateModule(FILE_RELOAD_INTERVAL_MILLIS,
        new String[] { GROUPSFILENAME, GROUPSFEEDFILENAME }, Optional.of(testExecutor));
    addVerification(CG_NAME3, USER3, CG_NAME3, AD_NAME3);

    assertThat(authenticate(module, CG_NAME3)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME3, GroupMemberships.make(USER3_GROUPS));
  }

  // User4 is in nested groups, overlapping groups and both group files.
  public void testUser4() {
    GroupsUpdateModule module = new GroupsUpdateModule(FILE_RELOAD_INTERVAL_MILLIS,
        new String[] { GROUPSFILENAME, GROUPSFEEDFILENAME }, Optional.of(testExecutor));
    addVerification(CG_NAME4, USER4, CG_NAME4, AD_NAME4);

    assertThat(authenticate(module, CG_NAME4)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME4, GroupMemberships.make(USER4_GROUPS));
  }

  // Tests User5 is in nested groups, overlapping groups and both group files.
  public void testUser5() {
    GroupsUpdateModule module = new GroupsUpdateModule(FILE_RELOAD_INTERVAL_MILLIS,
        new String[] { GROUPSFILENAME, GROUPSFEEDFILENAME }, Optional.of(testExecutor));
    addVerification(CG_NAME5, USER5, CG_NAME5, AD_NAME5);

    assertThat(authenticate(module, CG_NAME5)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME5, GroupMemberships.make(USER5_GROUPS));
  }

  public void testUser5WithExistingGroups() {
    GroupsUpdateModule module = new GroupsUpdateModule(FILE_RELOAD_INTERVAL_MILLIS,
        new String[] { GROUPSFILENAME, GROUPSFEEDFILENAME }, Optional.of(testExecutor));

    Credential user = AuthnPrincipal.make(USER5, CG_NAME5, AD_NAME5);
    ImmutableSet.Builder<Group> groups = ImmutableSet.builder();
    groups.add(Group.make(SUBSUBGROUP1, NAMESPACE4, DOMAIN4));
    
    addVerificationWithGroups(CG_NAME5, user, groups.build());

    assertThat(authenticate(module, CG_NAME5)).isEqualTo(VerificationStatus.VERIFIED);
    // The SUBSUBGROUP1 is resolved from other authn modules, then the groups module
    // resolve GROUP1 and GROUP3 (refer above test case). Since SUBSUBGROUP1 is in
    // SUBGROUP1, so the total groups include GROUP1, SUBGROUP1, SUBSUBGROUP1 and GROUP3.
    assertVerification(VerificationStatus.VERIFIED, CG_NAME5,
        GroupMemberships.make(USER5_GROUPS_WITH_EXIST_GROUPS));
  }

  public void testDataReloading() throws Exception {
    // user groups in writable tmp file.
    File groupsFile = File.createTempFile("policy", "groups");
    groupsFile.deleteOnExit();
    groupsFile.setWritable(true);
    Files.copy(new File(GROUPSFILENAME), groupsFile);

    // user feed groups in writable tmp file.
    File groupsFeedFile = File.createTempFile("policy", "groupsfeed");
    groupsFeedFile.deleteOnExit();
    groupsFeedFile.setWritable(true);
    Files.copy(new File(GROUPSFEEDFILENAME), groupsFeedFile);

    GroupsUpdateModule module = new GroupsUpdateModule(FILE_RELOAD_INTERVAL_MILLIS,
        new String[] { groupsFile.getAbsolutePath(), groupsFeedFile.getAbsolutePath()},
        Optional.of(testExecutor));

    // verifies the group info from original file.
    addVerification(CG_NAME1, USER1, CG_NAME1, AD_NAME1);
    assertThat(authenticate(module, CG_NAME1)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME1, GroupMemberships.make(USER1_GROUPS));

    resetSession();
    addVerification(CG_NAME2, USER2, CG_NAME2, AD_NAME2);
    assertThat(authenticate(module, CG_NAME2)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME2, GroupMemberships.make(USER2_GROUPS));

    resetSession();
    addVerification(CG_NAME3, USER3, CG_NAME3, AD_NAME3);
    assertThat(authenticate(module, CG_NAME3)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME3, GroupMemberships.make(USER3_GROUPS));

    resetSession();
    addVerification(CG_NAME4, USER4, CG_NAME4, AD_NAME4);
    assertThat(authenticate(module, CG_NAME4)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME4, GroupMemberships.make(USER4_GROUPS));

    resetSession();
    addVerification(CG_NAME5, USER5, CG_NAME5, AD_NAME5);
    assertThat(authenticate(module, CG_NAME5)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME5, GroupMemberships.make(USER5_GROUPS));

    // waits till the groups_update2.enterprise file is update.
    MemberToGroupsResolverMap map1 = module.getMemberGroupsProvider(0).getResolver();
    Thread.sleep(FILE_TIMESTAMP_PRECISION_MILLIS); // ensure a new timestamp after write.
    Files.write(Files.toByteArray(new File(GROUPSFILENAME2)), groupsFile);
    MemberToGroupsResolverMap map2 = module.getMemberGroupsProvider(0).getResolver();
    while (map1.equals(map2)) {
      Thread.sleep(WAIT_FOR_MAP_REGENERATE); 
      map2 = module.getMemberGroupsProvider(0).getResolver();
    }

    // verifies the group info from updated groups_update2.enterprise file.
    resetSession();
    addVerification(CG_NAME1, USER1, CG_NAME1, AD_NAME1);
    assertThat(authenticate(module, CG_NAME1)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME1, GroupMemberships.make(USER1_GROUPS2));

    resetSession();
    addVerification(CG_NAME2, USER2, CG_NAME2, AD_NAME2);
    assertThat(authenticate(module, CG_NAME2)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME2, GroupMemberships.make(USER2_GROUPS2));

    resetSession();
    addVerification(CG_NAME3, USER3, CG_NAME3, AD_NAME3);
    assertThat(authenticate(module, CG_NAME3)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME3, GroupMemberships.make(USER3_GROUPS2));

    resetSession();
    addVerification(CG_NAME4, USER4, CG_NAME4, AD_NAME4);
    assertThat(authenticate(module, CG_NAME4)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME4, GroupMemberships.make(USER4_GROUPS2));

    resetSession();
    addVerification(CG_NAME5, USER5, CG_NAME5, AD_NAME5);
    assertThat(authenticate(module, CG_NAME5)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME5, GroupMemberships.make(USER5_GROUPS2));

    // waits till the groups_update_feed2.enterprise file is update.
    map1 = module.getMemberGroupsProvider(1).getResolver();
    Thread.sleep(FILE_TIMESTAMP_PRECISION_MILLIS); // ensure a new timestamp after write.
    Files.write(Files.toByteArray(new File(GROUPSFEEDFILENAME2)), groupsFeedFile);
    map2 = module.getMemberGroupsProvider(1).getResolver();
    while (map1.equals(map2)) {
      Thread.sleep(WAIT_FOR_MAP_REGENERATE); 
      map2 = module.getMemberGroupsProvider(1).getResolver();
    }

    // verifies the group info from updated groups_update2.enterprise file.
    resetSession();
    addVerification(CG_NAME1, USER1, CG_NAME1, AD_NAME1);
    assertThat(authenticate(module, CG_NAME1)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME1, GroupMemberships.make(USER1_GROUPS3));

    resetSession();
    addVerification(CG_NAME2, USER2, CG_NAME2, AD_NAME2);
    assertThat(authenticate(module, CG_NAME2)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME2, GroupMemberships.make(USER2_GROUPS3));

    resetSession();
    addVerification(CG_NAME3, USER3, CG_NAME3, AD_NAME3);
    assertThat(authenticate(module, CG_NAME3)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME3, GroupMemberships.make(USER3_GROUPS3));

    resetSession();
    addVerification(CG_NAME4, USER4, CG_NAME4, AD_NAME4);
    assertThat(authenticate(module, CG_NAME4)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME4, GroupMemberships.make(USER4_GROUPS3));

    resetSession();
    addVerification(CG_NAME5, USER5, CG_NAME5, AD_NAME5);
    assertThat(authenticate(module, CG_NAME5)).isEqualTo(VerificationStatus.VERIFIED);
    assertVerification(VerificationStatus.VERIFIED, CG_NAME5, GroupMemberships.make(USER5_GROUPS3));
  }

  private void addUnverifiedCredential(
       String cgName, String username, String cg, String ad) {
    defaultState.addUnverifiedCredential(cgName, username, cg, ad);
  }

  private void addVerification(
       String cgName, String username, String cg, String ad) {
    defaultState.addVerification(cgName, username, cg, ad);
  }

  private void addVerificationWithGroups(
      String cgName, Credential user, Set<Group> groups) {
    defaultState.addVerificationWithGroups(cgName, user, groups);
  }

  private void resetSession() {
    defaultState.resetSession();
  }

  private VerificationStatus authenticate(GroupsUpdateModule module, String cgName) {
    return authenticate(module, cgName, defaultState);
  }

  private VerificationStatus authenticate(
      GroupsUpdateModule module, String cgName, TestState state) {
    AuthnMechanism groupsMech = state.getGroupsMechForCGName(cgName);
    return AuthnController.invokeModule(module, state.session.getView(groupsMech), state.session);
  }

  private void assertVerification(TestState state,
      String cgName, VerificationStatus expectedStatus, Credential... expectedCredentials) {
    AuthnMechanism groupsMech = state.getGroupsMechForCGName(cgName);
    Set<Verification> verifications =
        ImmutableSet.copyOf(state.session.getView(groupsMech).getVerifications());
    assertThat(verifications.size()).isEqualTo(1);
    Verification verification = Iterables.get(verifications, 0);
    assertThat(verification.getStatus()).isEqualTo(expectedStatus);
    assertThat(verification.getCredentials())
        .isEqualTo(ImmutableSet.copyOf(expectedCredentials));
  }

  private void assertVerification(VerificationStatus expectedStatus,
     String cgName, Credential... expectedCredentials) {
    assertVerification(defaultState, cgName, expectedStatus, expectedCredentials);
  }
  
  private static class TestScheduledExecutorService extends ScheduledThreadPoolExecutor {
    
    public TestScheduledExecutorService() {
      super(1);
    }
    
    @Override
    public ScheduledFuture<?> scheduleWithFixedDelay(
        Runnable command, long initialDelay, long delay, TimeUnit unit) {
      // First time execution on current thread (eliminate timing issues with tests).
      command.run();
      return super.scheduleWithFixedDelay(command, initialDelay, delay, unit);
    }
  }
  
  static void setFinalField(Object dstObject, String fieldName, Object newValue) throws Exception {
    Field field = dstObject.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);

    Field modifiersField = Field.class.getDeclaredField("modifiers");
    modifiersField.setAccessible(true);
    modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

    field.set(dstObject, newValue);
 }
}
