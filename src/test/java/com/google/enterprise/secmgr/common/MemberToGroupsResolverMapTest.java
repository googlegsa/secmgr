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
package com.google.enterprise.secmgr.common;

import static com.google.common.truth.Truth.assertThat;

import com.google.enterprise.policychecker.AclUtil;
import com.google.enterprise.policychecker.GroupMembersMap;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.supergsa.security.AclGroup;
import com.google.enterprise.supergsa.security.AclPrincipal;

import junit.framework.Assert;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * Unit tests for {@link MemberToGroupsResolverMap}.
 */
@RunWith(JUnit4.class)
public class MemberToGroupsResolverMapTest {

  // Handy AclPrincipals that can be used by several test cases.
  private static final AclPrincipal ALICE = AclUtil.userNameToAclPrincipal("alice");
  private static final AclPrincipal BOB = AclUtil.userNameToAclPrincipal("bob");
  private static final AclPrincipal BOB_CASE_INSENSITIVE =
      AclUtil.userNameToAclPrincipalCaseInsensitive("Bob");
  private static final AclPrincipal MARK_CASE_SENSITIVE = AclUtil.userNameToAclPrincipal("Mark");
  private static final AclPrincipal MARK_CASE_SENSITIVE_ALIAS =
      AclUtil.userNameToAclPrincipal("mark");
  private static final AclPrincipal JOHN_CASE_INSENSITIVE =
      AclUtil.userNameToAclPrincipalCaseInsensitive("John");
  private static final AclPrincipal JOHN_CASE_INSENSITIVE_ALIAS =
      AclUtil.userNameToAclPrincipalCaseInsensitive("john");
  private static final AclPrincipal SMITH_CASE_INSENSITIVE =
      AclUtil.userNameToAclPrincipalCaseInsensitive("smith");
  private static final AclPrincipal SMITH_CASE_INSENSITIVE_ALIAS1 =
      AclUtil.userNameToAclPrincipalCaseInsensitive("Smith");
  private static final AclPrincipal SMITH_CASE_INSENSITIVE_ALIAS2 =
      AclUtil.userNameToAclPrincipalCaseInsensitive("ſmith");
  private static final AclPrincipal ROSS_CASE_INSENSITIVE =
      AclUtil.userNameToAclPrincipalCaseInsensitive("ross");
  private static final AclPrincipal ROSS_CASE_INSENSITIVE_ALIAS1 =
      AclUtil.userNameToAclPrincipalCaseInsensitive("roSS");
  private static final AclPrincipal ROSS_CASE_INSENSITIVE_ALIAS2 =
      AclUtil.userNameToAclPrincipalCaseInsensitive("roß");
  private static final AclPrincipal ROSS_CASE_INSENSITIVE_ALIAS3 =
      AclUtil.userNameToAclPrincipalCaseInsensitive("roẞ");

  private static final AclPrincipal ENG = AclUtil.groupToAclPrincipal("eng");
  private static final AclPrincipal HR = AclUtil.groupToAclPrincipal("hr");
  private static final AclPrincipal FINANCE = AclUtil.groupToAclPrincipal("finance");

  private static final AclPrincipal HR_CASE_INSENSITIVE =
      AclUtil.groupToAclPrincipalCaseInsensitive("Hr");
  private static final AclPrincipal FINANCE_CASE_INSENSITIVE =
      AclUtil.groupToAclPrincipalCaseInsensitive("Finance");

  private static AclGroup buildAclGroup(AclPrincipal principal, AclPrincipal... members) {
    AclGroup.Builder builder = AclGroup.newBuilder();
    for (AclPrincipal member : members) {
      builder.addMembers(member);
    }
    return builder.setPrincipal(principal).build();
  }

  /**
   * Tests the builder functionality and documents some perhaps unexpected behavior.  Namely the
   * builder uses the same map for all subsequent calls to build(), so if further additions are made
   * to the underlying map they will show up in calls to the previously built
   * MemberToGroupsResolverMap objects.
   */
  @Test
  public void buildIncrementally() {
    MemberToGroupsResolverMap.Builder builder = MemberToGroupsResolverMap.builder();
    builder.normalizeAndPut(BOB, ENG);
    builder.normalizeAndPut(BOB, HR);

    MemberToGroupsResolverMap map = builder.build();
    assertThat(map.getAllGroupsForUser(BOB)).containsExactly(ENG, HR);

    builder.normalizeAndPut(BOB, FINANCE);
    MemberToGroupsResolverMap map2 = builder.build();
    assertThat(map2.getAllGroupsForUser(BOB)).containsExactly(ENG, HR, FINANCE);

    // The changes show up in the original map.
    assertThat(map.getAllGroupsForUser(BOB)).containsExactly(ENG, HR, FINANCE);
  }

  /**
   * Verifies IllegalArgumentExceptions are tHRown when trying to build the map with improper
   * arguments.
   */
  @Test
  public void buildWithInvalidArguments() {
    MemberToGroupsResolverMap.Builder builder = MemberToGroupsResolverMap.builder();

    try {
      builder.normalizeAndPut(BOB, ALICE);
      Assert.fail("Builder should not allow users as the second argument.");
    } catch (IllegalArgumentException expected) {
    }
  }
  
  /**
   * Verifies NullPoinerExceptions are tHRown when trying to build the map with null arguments.
   */
  @Test
  public void buildWithNullArguments() {
    MemberToGroupsResolverMap.Builder builder = MemberToGroupsResolverMap.builder();

    try {
      builder.normalizeAndPut(null, HR);
      Assert.fail("Builder should not allow null as the first argument.");
    } catch (NullPointerException expected) {
    }

    try {
      builder.normalizeAndPut(BOB, null);
      Assert.fail("Builder should not allow null as the second argument.");
    } catch (NullPointerException expected) {
    }
  }

  /**
   * Verifies the building commands can be chained together to make things easier to read.
   */
  @Test
  public void buildIncrementallyWithReturnArguments() {
    // Now do all the same stuff but in one line.
    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder()
        .normalizeAndPut(BOB, ENG)
        .normalizeAndPut(BOB, HR)
        .build();

    assertThat(map.getAllGroupsForUser(BOB)).containsExactly(ENG, HR);
  }

  /**
   * Builds an empty map and ensures no NPE or other undesirable behavior.
   */
  @Test
  public void buildEmptyMap() {
    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().build();
    assertThat(map).isEmpty();
  }

  /**
   * Verifies correct behavior on a simple group with one user and one group as members.
   */
  @Test
  public void buildFromSimpleGroup() {
    AclGroup group1 = buildAclGroup(ENG, ALICE, HR);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group1)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.getAllGroupsForUser(ALICE)).containsExactly(ENG);
    assertThat(map.keySet()).doesNotContain(ENG);
  }

  /**
   * Verifies that the mapping is correct for users who are members of the nested group but not of
   * the top-level group.
   */
  @Test
  public void buildFromNestedGroup() {
    AclGroup group1 = buildAclGroup(ENG, BOB, HR);
    AclGroup group2 = buildAclGroup(HR, ALICE);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group1)
        .put(group2)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.keySet()).doesNotContain(ENG);
    assertThat(map.getAllGroupsForUser(BOB)).containsExactly(ENG);
    assertThat(map.getAllGroupsForUser(ALICE)).containsExactly(ENG, HR);
  }

  /**
   * Verifies that the mapping is correct for users who are members of the both the nested group and
   * the top-level group.  Alice is in both groups.
   */
  @Test
  public void buildFromNestedGroupWithRedundantUsers() {
    AclGroup group1 = buildAclGroup(ENG, BOB, HR, ALICE);
    AclGroup group2 = buildAclGroup(HR, ALICE);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group1)
        .put(group2)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.keySet()).doesNotContain(ENG);
    assertThat(map.getAllGroupsForUser(BOB)).containsExactly(ENG);
    assertThat(map.getAllGroupsForUser(ALICE)).containsExactly(ENG, HR);
  }

  /**
   * Verifies that resolving groups will also resolve nested groups with multiple levels.
   * Alice is in groups of FINANCE, HR and ENG. Bob is in groups of HR and ENG.
   */
  @Test
  public void resolveMultipleLevelNestedGroupUsers() {
    AclGroup group1 = buildAclGroup(ENG, HR);
    AclGroup group2 = buildAclGroup(HR, FINANCE, BOB);
    AclGroup group3 = buildAclGroup(FINANCE, ALICE);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group1)
        .put(group2)
        .put(group3)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.keySet()).doesNotContain(ENG);
    assertThat(map.getAllGroupsForUser(BOB)).containsExactly(ENG, HR);
    assertThat(map.getAllGroupsForUser(ALICE)).containsExactly(ENG, HR, FINANCE);
  }

  /**
   * Verifies that resolving groups will also resolve nested case insensitive member groups
   * with multiple levels. Alice is in groups of FINANCE, HR and ENG. Bob is in groups
   * of HR and ENG.
   */
  @Test
  public void resolveMultipleLevelNestedCaseInsensitiveGroupMemberUsers() {
    AclGroup group1 = buildAclGroup(ENG, HR_CASE_INSENSITIVE);
    AclGroup group2 = buildAclGroup(HR, FINANCE_CASE_INSENSITIVE, BOB_CASE_INSENSITIVE);
    AclGroup group3 = buildAclGroup(FINANCE, ALICE);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group1)
        .put(group2)
        .put(group3)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.keySet()).doesNotContain(ENG);
    assertThat(map.getAllGroupsForUser(ALICE)).containsExactly(ENG, HR, FINANCE);
    assertThat(map.getAllGroupsForUser(BOB_CASE_INSENSITIVE)).containsExactly(ENG, HR);
  }

  /**
   * Verifies that cyclic groups defintions should be resolved correctly. Eng group has members of
   * HR and BOB, HR group has members of ENG and ALICE.
   */
  @Test
  public void resolveCyclicGroupUsers() {
    AclGroup group1 = buildAclGroup(ENG, HR, BOB);
    AclGroup group2 = buildAclGroup(HR, ENG, ALICE);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group1)
        .put(group2)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.keySet()).contains(ENG);
    assertThat(map.keySet()).contains(HR);
    assertThat(map.getAllGroupsForUser(BOB)).containsExactly(ENG, HR);
    assertThat(map.getAllGroupsForUser(ALICE)).containsExactly(ENG, HR);
  }

  /**
   * Verifies that case insensitive groups defintions should be resolved correctly. Eng group has
   * members of JOHN_CASE_INSENSITIVE and MARK_CASE_SENSITIVE.
   */
  @Test
  public void resolveCaseInsensitiveUsers() {
    AclGroup group1 = buildAclGroup(ENG, JOHN_CASE_INSENSITIVE, MARK_CASE_SENSITIVE);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group1)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.keySet()).doesNotContain(ENG);
    assertThat(map.getAllGroupsForUser(JOHN_CASE_INSENSITIVE)).containsExactly(ENG);
    assertThat(map.getAllGroupsForUser(JOHN_CASE_INSENSITIVE_ALIAS)).containsExactly(ENG);
    assertThat(map.getAllGroupsForUser(MARK_CASE_SENSITIVE)).containsExactly(ENG);
    assertThat(map.getAllGroupsForUser(MARK_CASE_SENSITIVE_ALIAS)).isEmpty();
  }

  /**
   * Verifies that case insensitive unicode groups defintions should be resolved correctly. Eng
   * group has members of SMITH_CASE_INSENSITIVE and ROSS_CASE_INSENSITIVE.
   */
  @Test
  public void resolveCaseInsensitiveUnicodeUsers() {
    AclGroup group1 = buildAclGroup(ENG, SMITH_CASE_INSENSITIVE, ROSS_CASE_INSENSITIVE);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group1)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.getAllGroupsForUser(SMITH_CASE_INSENSITIVE)).containsExactly(ENG);
    assertThat(map.getAllGroupsForUser(SMITH_CASE_INSENSITIVE_ALIAS1)).containsExactly(ENG);
    // Test the lower case long s - 'ſ'
    assertThat(map.getAllGroupsForUser(SMITH_CASE_INSENSITIVE_ALIAS2)).containsExactly(ENG);
    assertThat(map.getAllGroupsForUser(ROSS_CASE_INSENSITIVE)).containsExactly(ENG);
    assertThat(map.getAllGroupsForUser(ROSS_CASE_INSENSITIVE_ALIAS1)).containsExactly(ENG);
    // Test the lower case sharp s - 'ß'
    assertThat(map.getAllGroupsForUser(ROSS_CASE_INSENSITIVE_ALIAS2)).containsExactly(ENG);
    // Test the upper case sharp s - 'ẞ'
    assertThat(map.getAllGroupsForUser(ROSS_CASE_INSENSITIVE_ALIAS3)).containsExactly(ENG);
  }

  @Test
  public void resolveEmptyDomain() {
    // how does the user object look coming from authentication module
    AuthnPrincipal authnUser = AuthnPrincipal.make("user", "namespace", "");

    // how does the same object look in groups database
    AclPrincipal aclUser = AclUtil.buildAclPrincipal(AclPrincipal.SCOPE.USER, "user",
        "namespace", "", AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE);

    AclGroup group = buildAclGroup(ENG, aclUser);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.getAllGroupsForUser(AclUtil.authnPrincipalToAclPrincipal(authnUser)))
        .containsExactly(ENG);
  }

  @Test
  public void resolveDomainCaseInsensitive() {
    // how does the user object look coming from authentication module
    AuthnPrincipal authnUser = AuthnPrincipal.make("user", "namespace", "DOMAIN");

    // how does the same object look in groups database
    AclPrincipal aclUser = AclUtil.buildAclPrincipal(AclPrincipal.SCOPE.USER, "user",
        "namespace", "domain", AclPrincipal.CaseSensitivity.EVERYTHING_CASE_INSENSITIVE);

    AclGroup group = buildAclGroup(ENG, aclUser);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.getAllGroupsForUser(AclUtil.authnPrincipalToAclPrincipal(authnUser)))
        .containsExactly(ENG);
  }

  @Test
  public void resolveUserWithUnnormalizedDomainAndGroupWithUnnormalizedDomain() {
    // how does the user object look coming from authentication module
    AuthnPrincipal authnUser = AuthnPrincipal.make("user", "namespace", "domain.com");

    // how does the same object look in groups database
    AclPrincipal aclUser = AclUtil.buildAclPrincipal(AclPrincipal.SCOPE.USER, "user",
        "namespace", "domain.com", AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE);

    AclGroup group = buildAclGroup(ENG, aclUser);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.getAllGroupsForUser(AclUtil.authnPrincipalToAclPrincipal(authnUser)))
        .containsExactly(ENG);
  }

  @Test
  public void resolveUserWithUnnormalizedDomainAndGroupWithNormalizedDomain() {
    // how does the user object look coming from authentication module
    AuthnPrincipal authnUser = AuthnPrincipal.make("user", "namespace", "domain.com");

    // how does the same object look in groups database
    AclPrincipal aclUser = AclUtil.buildAclPrincipal(AclPrincipal.SCOPE.USER, "user",
        "namespace", "domain", AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE);

    AclGroup group = buildAclGroup(ENG, aclUser);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.getAllGroupsForUser(AclUtil.authnPrincipalToAclPrincipal(authnUser)))
        .containsExactly(ENG);
  }

  @Test
  public void resolveUserWithUnnormalizedDomainAndGroupWithNormalizedDomain2() {
    // how does the user object look coming from authentication module
    AuthnPrincipal authnUser = AuthnPrincipal.make("user", "namespace", "domain.com.hk");

    // how does the same object look in groups database
    AclPrincipal aclUser = AclUtil.buildAclPrincipal(AclPrincipal.SCOPE.USER, "user",
        "namespace", "domain", AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE);

    AclGroup group = buildAclGroup(ENG, aclUser);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.getAllGroupsForUser(AclUtil.authnPrincipalToAclPrincipal(authnUser)))
        .containsExactly(ENG);
  }

  @Test
  public void resolveUserWithUnnormalizedDomainAndCaseInsensitive() {
    // how does the user object look coming from authentication module
    AuthnPrincipal authnUser = AuthnPrincipal.make("user", "namespace", "DOMAIN.com");

    // how does the same object look in groups database
    AclPrincipal aclUser = AclUtil.buildAclPrincipal(AclPrincipal.SCOPE.USER, "user",
        "namespace", "domain", AclPrincipal.CaseSensitivity.EVERYTHING_CASE_INSENSITIVE);

    AclGroup group = buildAclGroup(ENG, aclUser);

    GroupMembersMap groups = GroupMembersMap.builder()
        .put(group)
        .build();

    MemberToGroupsResolverMap map = MemberToGroupsResolverMap.builder().merge(groups).build();
    assertThat(map.getAllGroupsForUser(AclUtil.authnPrincipalToAclPrincipal(authnUser)))
        .containsExactly(ENG);
  }
}
