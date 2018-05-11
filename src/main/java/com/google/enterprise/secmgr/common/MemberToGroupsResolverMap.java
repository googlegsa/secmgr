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

import com.google.common.base.Preconditions;
import com.google.common.collect.Sets;
import com.google.enterprise.policychecker.AclPrincipalComparator;
import com.google.enterprise.policychecker.GroupMembersMap;
import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.enterprise.supergsa.security.Domain;

import com.ibm.icu.text.Normalizer2;

import java.util.AbstractMap;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListMap;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Map from member to the set of group(s) it belongs to.  The set of groups should be exhaustive,
 * including all nested groups.
 */
@Immutable
public final class MemberToGroupsResolverMap extends AbstractMap<AclPrincipal, Set<AclPrincipal>> {

  /**
   * An object for standard Unicode normalization.
   */
  private static final Normalizer2 NORMALIZER =
      Normalizer2.getInstance(null, "nfkc_cf", Normalizer2.Mode.COMPOSE);

  private final Map<AclPrincipal, Set<AclPrincipal>> memberToGroupsMap;

  protected MemberToGroupsResolverMap(Map<AclPrincipal, Set<AclPrincipal>> memberToGroupsMap) {
    this.memberToGroupsMap = memberToGroupsMap;
  }

  /**
   * Returns a normalized case insensitive principal from input.
   */
  private static AclPrincipal makeCaseInsensitiveNormalizedPrincipal(AclPrincipal from) {
    AclPrincipal.Builder principal = AclPrincipal.newBuilder()
        .setScope(from.getScope())
        .setCaseSensitive(AclPrincipal.CaseSensitivity.EVERYTHING_CASE_INSENSITIVE)
        .setName(NORMALIZER.normalize(from.getName()));

    if (from.hasNameSpace()) {
      principal.setNameSpace(NORMALIZER.normalize(from.getNameSpace()));
    }
    if (from.hasDomain()) {
      principal.setDomain(Domain.newBuilder()
          .setName(NORMALIZER.normalize(from.getDomain().getName()))
          .setType(from.getDomain().getType()));
    }
    return principal.build();
  }

  /**
   * Creates a normalized domain principal from input.
   */
  private static AclPrincipal makeNormalizedDomainPrincipal(AclPrincipal from) {
    if (!from.hasDomain()) {
      return from;
    }
    return AclPrincipal.newBuilder(from)
        .setDomain(Domain.newBuilder()
            .setName(IdentityUtil.normalizeDomain(from.getDomain().getName()))
            .setType(from.getDomain().getType()).build())
        .build();
  }

  /**
   * Simple builder to add user/group associations and build from {@link GroupMembersMap} objects.
   */
  @ThreadSafe
  public static class Builder {

    private ConcurrentSkipListMap<AclPrincipal, Set<AclPrincipal>> memberToGroupsMap;

    public Builder() {
      memberToGroupsMap = new ConcurrentSkipListMap<>(new AclPrincipalComparator());
    }

    /**
     * Builds the {@link MemberToGroupsResolverMap} and returns it.  Note that doing things to the
     * builder after calling {@code build()} will modifying the underlying map.  Be careful
     * with what you are doing here.  In most cases it's probably better to chain the
     * constructor together with all modifiers and a call to {@code build()}.  See the unittest
     * for more details.
     */
    public MemberToGroupsResolverMap build() {
      return new MemberToGroupsResolverMap(memberToGroupsMap);
    }

    /**
     * Updates the contents of the map from merging this {@link GroupMembersMap}. 
     */
    public Builder merge(GroupMembersMap groups) {
      for (Map.Entry<AclPrincipal, Set<AclPrincipal>> entry : groups.entrySet()) {
        for (AclPrincipal member : entry.getValue()) {
          normalizeAndPut(member, entry.getKey());
        }
      }
      return this;
    }

    /**
     * Checks and normalizes the user if it is case insensitive. Puts member, group pair into the
     * map.
     */
    public Builder normalizeAndPut(AclPrincipal principal, AclPrincipal group) {
      Preconditions.checkNotNull(principal);
      Preconditions.checkNotNull(group);
      Preconditions.checkArgument(group.getScope() == AclPrincipal.SCOPE.GROUP);

      AclPrincipal member = principal;
      if (principal.getCaseSensitive()
          == AclPrincipal.CaseSensitivity.EVERYTHING_CASE_INSENSITIVE) {
        member = makeCaseInsensitiveNormalizedPrincipal(principal);
      }
      return put(member, group);
    }

    /**
     * Puts the member and group pair into the map.
     */
    private synchronized Builder put(AclPrincipal member, AclPrincipal group) {
      Set<AclPrincipal> groups = memberToGroupsMap.get(member);
      if (groups != null) {
        groups.add(group);
      } else {
        Set<AclPrincipal> newGroups = new HashSet<>();
        newGroups.add(group);
        memberToGroupsMap.put(member, newGroups);
      }
      return this;
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Returns all groups which the user belongs to for both case sensitive and case insensitive.
   */
  public Set<AclPrincipal> getAllGroupsForUser(AclPrincipal user) {
    Set<AclPrincipal> membership = new HashSet<>(getGroupsForUser(user));
    AclPrincipal userCaseInsensitive = makeCaseInsensitiveNormalizedPrincipal(user);
    Set<AclPrincipal> membershipCaseInsensitive = getGroupsForUser(userCaseInsensitive);
    membership.addAll(membershipCaseInsensitive);

    // Add checking groups for user with ".com" domain.
    AclPrincipal userNormalizedDomain = makeNormalizedDomainPrincipal(user);
    Set<AclPrincipal> membershipNormalizedDomain = getGroupsForUser(userNormalizedDomain);
    membership.addAll(membershipNormalizedDomain);
    AclPrincipal userNormalizedDomainCaseInsensitive =
        makeCaseInsensitiveNormalizedPrincipal(userNormalizedDomain);
    Set<AclPrincipal> membershipNormalizedDomainCaseInsensitive =
        getGroupsForUser(userNormalizedDomainCaseInsensitive);
    membership.addAll(membershipNormalizedDomainCaseInsensitive);

    return membership;
  }

  @Override
  public Set<Map.Entry<AclPrincipal, Set<AclPrincipal>>> entrySet() {
    return Collections.unmodifiableSet(memberToGroupsMap.entrySet());
  }

  /**
   * Returns all groups which the user belongs to. It handles nested groups scenario.
   */
  private Set<AclPrincipal> getGroupsForUser(AclPrincipal user) {
    Set<AclPrincipal> returnedMembership = new HashSet<>();
    LinkedList<AclPrincipal> cachedMembership = new LinkedList<>();
    cachedMembership.add(user);
    while (!cachedMembership.isEmpty()) {
      // Group is case neutral when saying it has members. Since we have the case where group A
      // is a case sensitive group member of B and a case insensitive group member of group C.
      // We have to form two versions of group A to look up which group has it as member.
      AclPrincipal memberCaseSensitive = cachedMembership.remove(0);
      AclPrincipal memberCaseInsensitive =
          makeCaseInsensitiveNormalizedPrincipal(memberCaseSensitive);
      Set<AclPrincipal> groups = null;
      Set<AclPrincipal> groupsMemberCaseSensitive = memberToGroupsMap.get(memberCaseSensitive);
      Set<AclPrincipal> groupsMemberCaseInsensitive = memberToGroupsMap.get(memberCaseInsensitive);

      if (groupsMemberCaseSensitive == null && groupsMemberCaseInsensitive == null) {
        continue;
      } else if (groupsMemberCaseSensitive == null && groupsMemberCaseInsensitive != null) {
        groups = groupsMemberCaseInsensitive;
      } else if (groupsMemberCaseSensitive != null && groupsMemberCaseInsensitive == null) {
        groups = groupsMemberCaseSensitive;
      } else {
        groups = Sets.union(groupsMemberCaseSensitive, groupsMemberCaseInsensitive);
      }

      for (AclPrincipal group : groups) {
        if (returnedMembership.add(group)) {
          cachedMembership.add(group);
        }
      }
    }
    return returnedMembership;
  }
}
