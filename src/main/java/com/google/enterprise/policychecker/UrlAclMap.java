// Copyright 2007 Google Inc.
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

package com.google.enterprise.policychecker;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSortedSet;
import com.google.common.labs.matcher.UrlMapping;
import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.enterprise.supergsa.security.PolicyAcl;

import java.util.Comparator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Base class for a mapping from Urls to Acls.
 */
public class UrlAclMap implements Authorizer {

  protected Group userGroupStore;
  protected final UrlMapping<Acl> mapping;
  protected final Map<String, Acl> patternMap;

  // Should be 'true' whenever the underlying userGroupStore, mapping, or patternMap have changed
  // state since the last time resetHasChanged() has been called.
  private volatile boolean hasChanged;

  private static class PolicyAclComparator implements Comparator<PolicyAcl> {
    @Override
    public int compare(PolicyAcl a, PolicyAcl b) {
      if (a == null) {
        if (b == null) {
          return 0;
        }
        return -1;
      }
      if (b == null) {
        return 1;
      }
      int patternComparison = a.getPattern().compareTo(b.getPattern());
      if (patternComparison != 0) {
        return patternComparison;
      }
      // Ensure the equals contract is observed.
      if (a.equals(b)) {
        return 0;
      }
      return a.toString().compareTo(b.toString());
    }

    @Override
    public boolean equals(Object o) {
      return o instanceof PolicyAclComparator;
    }

    @Override
    public int hashCode() {
      return 1;
    }
  }

  public UrlAclMap() {
    this(new Group("everyone"),
         new UrlMapping<Acl>(), new TreeMap<String, Acl>());
  }

  public UrlAclMap(Group userGroupStore, UrlMapping<Acl> mapping, Map<String, Acl> patternMap) {
    this.userGroupStore = userGroupStore;
    this.mapping = mapping;
    if (patternMap == null) {
      this.patternMap = new TreeMap<String, Acl>();
    } else {
      this.patternMap = patternMap;
    }
  }

  /**
   * Returns an immutable view of the groups.
   */
  public ImmutableGroup groups() {
    return new ImmutableGroup(getUserGroupStore());
  }

  @Override
  public String toString() {
    return "groups: " + getUserGroupStore() +
        "patterns: " + patternMap;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof UrlAclMap)) {
      return false;
    }
    UrlAclMap m = (UrlAclMap) o;
    // This is only used for testing right now, but if correctness in a multi-threaded environment
    // is ever need, the following questions will need to be answered.
    // Need to compare mapping as well?
    // Synchronization?
    return getUserGroupStore().equals(m.groups()) && patternMap.equals(m.patternMap);
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  /**
   * Get the membership information of a particular group.
   *
   * @param principal the AclPrincipal identifying the group to be queried
   * @return the group or null if no such group exists
   */
  public Group getGroup(AclPrincipal principal) {
    return getUserGroupStore().getGroup(principal);
  }

  /**
   * Get the membership information of a particular user.
   *
   * @param principal the AclPrincipal identifying the user to be queried
   * @return the user or null if no such user exists
   */
  public User getUser(AclPrincipal principal) {
    return getUserGroupStore().getUser(principal);
  }

  /**
   * Checks if a particular user is defined.
   *
   * @param principal the AclPrincipal identifying the user to find
   * @return true iff the given user is defined
   */
  public boolean contains(AclPrincipal principal) {
    return getUserGroupStore().contains(principal);
  }

  /**
   * Retrieves a sorted list of all the Group names with no duplicates.
   *
   * @return a list of the names of all the groups in this contract
   */
  public ImmutableList<AclPrincipal> getAllGroupNames() {
    return getUserGroupStore().getGroups();
  }

  /**
   * Retrieves a sorted list of all the Users in a given Group with no duplicates.
   *
   * @param principal the AclPrincipal identifying the group to retrieve members for
   * @return a list of the names of all the Users in the given group
   */
  public ImmutableList<AclPrincipal> getUsersFromGroup(AclPrincipal principal) {
    Group group = getGroup(principal);
    if (group != null) {
      return group.getUsers();
    }
    return ImmutableList.of();
  }

  /**
   * Retrieves a sorted list of all the Groups in a given Group with no duplicates.
   *
   * @param principal the AclPrincipal identifying the group to retrieve members for
   * @return a list of the names of all the Groups in the given group
   */
  public ImmutableList<AclPrincipal> getGroupsFromGroup(AclPrincipal principal) {
    Group group = getGroup(principal);
    if (group != null) {
      return group.getGroups();
    }
    return ImmutableList.of();
  }

  /**
   * Gets a Map of all (Pattern,ACL) mappings whose pattern matches the specified URL.
   *
   * @param url The URL for which you want ACLs.
   * @return Map of all (Pattern,ACL) mappings whose pattern matches the specified URL
   */
  public ImmutableMap<String, Acl> getAllMatches(String url) {
    synchronized (mapping) {
      return mapping.getMappings(url);
    }
  }

  /**
   * Gets the ACL best associated with the specified URL.
   *
   * @param url The URL for which you want ACLs.
   * @return The ACL best associated with the specified URL
   */
  @Override
  public Acl get(String url) {
    synchronized (mapping) {
      return mapping.getBestValue(url);
    }
  }

  /**
   * Checks if a given pattern is mapped to an ACL.
   *
   * @param pattern a UrlPattern
   * @return true iff pattern is mapped to an ACL
   */
  public boolean containsMapping(String pattern) {
    return null != getAclForPattern(pattern);
  }

  /**
   * Returns the Acl mapped to a given pattern, or null if no such mapping
   * exists.
   *
   * @param pattern the UrlPattern key
   * @return the Acl mapped to the given pattern, or null if the pattern
   * is not mapped
   */
  public Acl getAclForPattern(String pattern) {
    synchronized (patternMap) {
      return patternMap.get(pattern);
    }
  }

  /**
   * Dump a representation of all the pattern mappings
   * @param metapattern A pattern that is matched against the patterns
   *
   * @return List of all PolicyAcls for which the specified
   * metapattern matches the pattern in that PolicyAcl
   */
  public ImmutableList<PolicyAcl> getAllMappingsByMetapattern(String metapattern) {
    ImmutableSortedSet.Builder<PolicyAcl> b = ImmutableSortedSet.orderedBy(
        new PolicyAclComparator());
    Pattern p = null;
    if (!"".equals(metapattern)) {
      try {
        p = Pattern.compile(metapattern);
      } catch (PatternSyntaxException e) {
        return b.build().asList();
      }
    }

    synchronized (patternMap) {
      for (Entry<String, Acl> e : patternMap.entrySet()) {
        if (p == null || p.matcher(e.getKey()).matches()) {
          PolicyAcl acl = PolicyAcl.newBuilder()
              .setPattern(e.getKey())
              .setAcl(e.getValue().toGsaAcl())
              .build();
          b.add(acl);
        }
      }
    }
    return b.build().asList();
  }

  /**
   * Add a mapping from a single pattern to a single ACL. Note: the pattern
   * language is not specified by this interface.
   *
   * @param patternString The pattern to associate.
   * @param acl The ACL to associate it with.
   */
  public void put(String patternString, Acl acl) {
    getUserGroupStore().addPrincipals(acl.getPrincipals());
    synchronized (patternMap) {
      patternMap.put(patternString, acl);
    }
    synchronized (mapping) {
      mapping.put(patternString, acl);
    }
    hasChanged = true;
  }

  /**
   * Add a set of Mappings from patterns to ACLs.
   *
   * @param patternMap a Map<Sring, String> giving pattern to ACL mappings.
   */
  public void putAll(Map<String, Acl> patternMap) {
    for (Map.Entry<String, Acl> e : patternMap.entrySet()) {
      put(e.getKey(), e.getValue());
    }
  }

  /**
   * Remove a specified pattern.
   *
   * @param pattern The patterns to remove
   * @return true if the removal succeeded; false if the pattern did not exist
   */
  public boolean removePattern(String pattern) {
    if (!containsMapping(pattern)) {
      return false;
    }
    if (pattern == null) {
      return false;
    }
    synchronized (mapping) {
      mapping.remove(pattern);
    }
    synchronized (patternMap) {
      patternMap.remove(pattern);
    }
    hasChanged = true;
    return true;
  }

  /**
   * Adds a user to the group with the given name.  The caller may specify
   * whether to create the destination group if it does not already exist.
   *
   * @param principal the AclPrincipal identifying the user to add
   * @param group the AclPrincipal identifying the group to add the user to
   * @param createNew create a new group if group doesn't exist
   * @return true on success; false if no group exists with group and
   * createNew is false
   */
  public boolean addAclPrincipalToGroup(AclPrincipal principal, AclPrincipal group,
      boolean createNew) {
    if (!getUserGroupStore().contains(group) && !createNew) {
      return false;
    }
    Group g = getUserGroupStore().getGroup(group);
    if (g == null) {
      g = getUserGroupStore().addGroup(group);
    }
    g.addPrincipal(principal);
    hasChanged = true;
    return true;
  }

  /**
   * Removes a given member from a given group.
   *
   * @param memberId the principal of the member to remove
   * @param groupId the id of the group to remove member from
   * @return true on success; false if the user or group doesn't exist, or if
   * the user is not a member of the specified group
   */
  public boolean removeMember(AclPrincipal memberId, AclPrincipal groupId) {
    Group group = getGroup(groupId);
    if (group == null) {
      return false;
    }
    boolean changed;
    if (memberId.getScope() == AclPrincipal.SCOPE.USER) {
      changed = group.removePrincipal(new User(memberId));
    } else {
      changed = group.removePrincipal(new Group(memberId));
    }
    if (changed) {
      hasChanged = true;
    }
    return changed;
  }

  /**
   * Adds a group definition to the groups list.
   *
   * @param group group to add
   * @throws IllegalArgumentException if groupDef is not correctly formatted
   *
   * Note that we can't validate more than this because we can't expect the user
   * to upload groups in hierarchical order, so it doesn't actually make sense
   * to expect the members of the group being added to be previously defined.
   */
  public void addGroup(Group group) {
    getUserGroupStore().addGroup(group);
    hasChanged = true;
  }

  /**
   * Removes a group definition from the groups list.  Note: this clears the
   * membership list from the group, but does not remove the group entirely.
   *
   * @param principal AclPrincipal identifying the group to remove
   * @return true if the removal succeeded; false if the group did not exist
   */
  public boolean removeGroup(AclPrincipal principal) {
    Group group = getUserGroupStore().getGroup(principal);
    if (group != null) {
      group.clear();
      hasChanged = true;
    }
    return true;
  }

  /**
   * Adds a single UrlPattern-Acl mapping from the given UrlPattern and Acl.
   * Will overwrite any existing mapping on the same UrlPattern.
   *
   * @param pattern a UrlPattern
   * @param acl an Acl
   */
  public void addPattern(String pattern, Acl acl) {
    synchronized (patternMap) {
      if (acl.equals(patternMap.get(pattern))) {
        return;
      }
    }
    put(pattern, acl);
  }

  /**
   * If the underlying acl or group definition maps have been modified by
   * any of the setters, this function will return true until resetHasChanged
   * is called.
   * @return true iff a setter has changed the underlying acl/group state and
   * resetHasChanged has not yet been called
   */
  public boolean hasChanged() {
    return hasChanged;
  }

  public void resetHasChanged() {
    hasChanged = false;
  }

  /**
   * Get the UserGroupStore associated with this UrlAclMap.
   * @return the user group store associated with this UrlAclMap
   */
  private Group getUserGroupStore() {
    return userGroupStore;
  }
}
