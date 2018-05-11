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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSortedSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Ordering;
import com.google.common.collect.Sets;
import com.google.enterprise.supergsa.security.AclGroup;
import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.enterprise.supergsa.security.Domain;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.Nullable;

/**
 * Group is the compound form of Principal: a collection of Principals. A Group
 * may contain Users or Groups <i>directly</i>, if these Users or Groups or
 * <i>indirectly</i> (through containment in a sub-Group).
 */
public class Group implements Principal {
  private static final String DEFAULT_NAMESPACE = "Default";

  private AclPrincipal principal;

  protected final Map<AclPrincipal, User> users;
  protected final Map<AclPrincipal, Group> groups;

  /**
   * Build a group from an AclGroup protocol buffer.  Note that in this version the references to
   * groups and users will not be canonicalized.
   * @param group the group to convert from
   * @return the Group equivalent of the protocol buffer version of this group.  The
   * statement group.equals(AclGroup.fromAclGroup(group).toAclGroup()) will be true.
   */
  public static Group fromAclGroup(final AclGroup group) {
    AclPrincipal newGroup = group.getPrincipal();

    if (newGroup.getScope() != AclPrincipal.SCOPE.GROUP) {
      throw new IllegalArgumentException("AclGroup not well-formed: " + group);
    }
    Group grp = new Group(newGroup.getName(),
        newGroup.getNameSpace(),
        newGroup.getDomain());
    for (AclPrincipal principal : group.getMembersList()) {
      if (principal.getScope() == AclPrincipal.SCOPE.USER) {
        grp.addUser(new User(principal.getName(),
            principal.getNameSpace(),
            principal.getDomain()));
      } else {
        grp.addGroup(new Group(principal.getName(),
            principal.getNameSpace(),
            principal.getDomain()));
      }
    }
    return grp;
  }

  @SuppressWarnings("unused")
  protected Group() {
    throw new IllegalArgumentException();
    // prevents use of the default constructor
  }

  /**
   * Construct a group from the given name, with default namespace and no domain set.
   *
   * @param name The Group's name.
   * @throws IllegalArgumentException if the name is <code>null</code>.
   */
  public Group(final String name) {
    Preconditions.checkNotNull(name);
    principal = AclPrincipal.newBuilder()
        .setName(name)
        .setScope(AclPrincipal.SCOPE.GROUP)
        .setCaseSensitive(AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE)
        .setNameSpace(DEFAULT_NAMESPACE)
        .build();
    this.groups = new ConcurrentHashMap<AclPrincipal, Group>();
    this.users = new ConcurrentHashMap<AclPrincipal, User>();
  }

  /**
   * Construct a group from the given name, namespace and domain.
   *
   * @param name The Group's name.
   * @param namespace The Group's namespace.
   * @param domain The Group's domain.
   * @throws IllegalArgumentException if the name is <code>null</code> or empty string.
   */
  public Group(final String name, final String namespace, final Domain domain) 
      throws IllegalArgumentException {
    if (name == null || name.isEmpty()) {
      // A Group must have a non-null, non-empty name
      throw new IllegalArgumentException();
    }
    AclPrincipal.Builder builder = AclPrincipal.newBuilder();
    builder.setName(name);
    builder.setScope(AclPrincipal.SCOPE.GROUP);
    if (namespace == null || namespace.isEmpty()) {
      builder.setNameSpace(DEFAULT_NAMESPACE);
    } else {
      builder.setNameSpace(namespace);
    }
    // Do not assign domain if it is null or not default value.
    // Currently we only support domain type as NETBIOS.
    if (domain != null
        && !(domain.getName().isEmpty()
        && domain.getType() == Domain.DomainType.NETBIOS)) {
      builder.setDomain(Domain.newBuilder()
          .setName(domain.getName())
          .setType(domain.getType())
          .build());
    }
    builder.setCaseSensitive(AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE);
    principal = builder.build();
    this.groups = new ConcurrentHashMap<AclPrincipal, Group>();
    this.users = new ConcurrentHashMap<AclPrincipal, User>();
  }

  /**
   * Construct a group from the given principal.
   *
   * @param principal The principal to identify the group
   * @throws IllegalArgumentException if the name is <code>null</code>
   */
  public Group(final AclPrincipal principal) {
    Preconditions.checkNotNull(principal);
    if (principal.getScope() != AclPrincipal.SCOPE.GROUP) {
      throw new IllegalArgumentException();
    }
    this.principal = principal;
    this.groups = new ConcurrentHashMap<AclPrincipal, Group>();
    this.users = new ConcurrentHashMap<AclPrincipal, User>();
  }

  /**
   * Returns a sorted, immutable list of all users contained in this group or sub-groups with no
   * duplicates. This function handles the cyclic groups scenario.
   */
  public ImmutableList<AclPrincipal> getUsers() {
    ImmutableSortedSet.Builder<AclPrincipal> builder = ImmutableSortedSet.orderedBy(
        new AclPrincipalComparator());
    List<Group> cachedSubGroups = Lists.<Group>newLinkedList();
    Set<Group> allSubGroups = Sets.<Group>newHashSet();
    builder.addAll(users.keySet());
    for (Group group : groups.values()) {
      cachedSubGroups.add(group);
      allSubGroups.add(group);
    }
    
    while (!cachedSubGroups.isEmpty()) {
      Group currentGroup = cachedSubGroups.remove(0);
      builder.addAll(currentGroup.getDirectAclPrincipalUsers());
      for (Group group : currentGroup.getDirectGroups()) {
        if (allSubGroups.contains(group)) {
          continue;
        }
        cachedSubGroups.add(group);
        allSubGroups.add(group);
      }
    }

    return builder.build().asList();
  }

  /**
   * Returns a sorted, immutable list of all groups contained in this group or sub-groups with no
   * duplicates. This function handles the cyclic groups scenario.
   */
  public ImmutableList<AclPrincipal> getGroups() {
    ImmutableSortedSet.Builder<AclPrincipal> builder = ImmutableSortedSet.orderedBy(
        new AclPrincipalComparator());
    List<Group> cachedSubGroups = Lists.<Group>newLinkedList();
    Set<Group> allSubGroups = Sets.<Group>newHashSet();
    builder.addAll(groups.keySet());
    for (Group group : groups.values()) {
      cachedSubGroups.add(group);
      allSubGroups.add(group);
    }
    
    while (!cachedSubGroups.isEmpty()) {
      Group currentGroup = cachedSubGroups.remove(0);
      builder.addAll(currentGroup.getDirectAclPrincipalGroups());
      for (Group group : currentGroup.getDirectGroups()) {
        if (allSubGroups.contains(group)) {
          continue;
        }
        cachedSubGroups.add(group);
        allSubGroups.add(group);
      }
    }
    return builder.build().asList();
  }

  /**
   * Returns true if this Group <code>equals</code> the given AclPrincipal,
   * or if this Group contains the parameter either directly or indirectly.
   * Note: two different Groups with the same name do not contain each other.
   *
   * @param principal the AclPrincipal identifier that may be a member of this Principal
   * @return true if the parameter is a member of this Group
   */
  public boolean contains(@Nullable AclPrincipal principal) {
    // If this is us, then we reflexively contain ourselves.
    if (this.principal.equals(principal)) {
      return true;
    }
    // If we directly contain the principal, then sweet.
    if (users.containsKey(principal) || groups.containsKey(principal)) {
      return true;
    }
    // Otherwise, we look to see if any of our groups contains this principal.
    for (Group group : groups.values()) {
      if (group.contains(principal)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Returns the Principal's AclPrincipal identifier, which may not be <code>null</code> or
   * empty.
   *
   * @return the Principal's AclPrincipal identifier
   */
  @Override
  public AclPrincipal getAclPrincipal() {
    return principal;
  }

  /**
   * Converts this group into the protocol buffer format convenient for serialization.
   *
   * @return the AclGroup equivalent of the protocol buffer version of this group.  The
   * statement group.equals(AclGroup.fromAclGroup(group).toAclGroup()) will be true for any group
   * returned from this function.  Note it may not be the case that
   * this.equals(AclGroup.fromAclGroup(this.toAclGroup())) because object references are not
   * canonicalized in fromAclGroup().
   */
  public AclGroup toAclGroup() {
    return AclGroup.newBuilder()
        .setPrincipal(getAclPrincipal())
        .addAllMembers(getDirectAclPrincipalUsers())
        .addAllMembers(getDirectAclPrincipalGroups())
        .build();
  }

  /**
   * Returns a short string representation of the Principal.
   *
   * @return a short string representation of the Principal.
   */
  public String getShortString() {
    StringBuilder sb = new StringBuilder();
    appendShortName(sb);
    return new String(sb);
  }

  private void appendShortName(StringBuilder sb) {
    sb.append("group:");
    sb.append(principal.getName());
  }

  /**
   * Returns a string representation of the Group which includes the group name, the names of its
   * subgroups / users, and the contents of its subgroups.
   *
   * @return a string representation of the Principal.
   */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    appendGroupContents(sb);
    sb.append("\n");
    TreeMap<AclPrincipal, Group> map = new TreeMap<AclPrincipal, Group>(
        new AclPrincipalComparator());
    map.putAll(groups);
    for (Entry<AclPrincipal, Group> e : map.entrySet()) {
      e.getValue().appendGroupContents(sb);
      sb.append("\n");
    }
    return new String(sb);
  }

  /**
   * Returns a string representation of the Group which includes the names of
   * its subgroups / users.
   *
   * @return a string representation of the Principal.
   */
  public String toSerializedString() {
    StringBuilder sb = new StringBuilder();
    appendGroupContents(sb);
    return new String(sb);
  }

  private void appendGroupContents(StringBuilder sb) {
    appendShortName(sb);
    Comparator<AclPrincipal> comparator = new AclPrincipalComparator();
    TreeMap<AclPrincipal, Principal> groupsMap = new TreeMap<AclPrincipal, Principal>(comparator);
    TreeMap<AclPrincipal, Principal> usersMap = new TreeMap<AclPrincipal, Principal>(comparator);
    groupsMap.putAll(groups);
    usersMap.putAll(users);
    appendPrincipals(sb, groupsMap);
    appendPrincipals(sb, usersMap);
  }

  private void appendPrincipals(StringBuilder sb, SortedMap<AclPrincipal, Principal> s) {
    for (Entry<AclPrincipal, Principal> e : s.entrySet()) {
      sb.append(" ");
      sb.append(e.getValue().getShortString());
    }
  }

  public String dumpToString() {
    StringBuilder sb = new StringBuilder();
    Comparator<AclPrincipal> comparator = new AclPrincipalComparator();
    TreeMap<AclPrincipal, Group> groupsMap = new TreeMap<AclPrincipal, Group>(comparator);
    groupsMap.putAll(groups);
    for (Entry<AclPrincipal, Group> e : groupsMap.entrySet()) {
      e.getValue().appendGroupContents(sb);
      sb.append("\n");
    }
    return new String(sb);
  }
  /**
   * Returns true if this Group directly contains the parameter Principal. This
   * means that the parameter was added directly to this Group, as opposed to
   * being a member of a sub-Group of one of the Groups directly contained in
   * this Group. Note: a Group never directly contains itself.
   *
   * @param principal the Principal that may be a member of this Group
   * @return true if the parameter is a direct member of this Group
   * @throws IllegalArgumentException if the Principal is neither a User nor
   *           Group
   */
  public boolean directlyContains(Principal principal) throws IllegalArgumentException {
    AclPrincipal name = principal.getAclPrincipal();
    if (principal instanceof User) {
      return users.containsKey(name);
    } else if (principal instanceof Group) {
      if (this.principal.equals(name)) { return false; }
      return groups.containsKey(name);
    } else {
      // User and Group are the only permitted kinds of Principal
      throw new IllegalArgumentException();
    }
  }

  /**
   * Add a Principal to this Group.
   *
   * @param principal the Principal to add
   * @throws IllegalArgumentException if the Principal is neither a User nor
   *           Group
   */
  public Principal addPrincipal(Principal principal) throws IllegalArgumentException {
    return addPrincipal(principal.getAclPrincipal());
  }

  public Principal addPrincipal(AclPrincipal principal) throws IllegalArgumentException {
    if (principal == null) {
      return null;
    }
    if (principal.getScope() == AclPrincipal.SCOPE.USER) {
      return addUser(principal);
    } else {
      return addGroup(principal);
    }
  }

  /**
   * Add a Collection of Principals to this Group.
   *
   * @param principals the Collection of Principals to add
   */
  public void addPrincipals(final Collection<Principal> principals) {
    if (principals == null) { return; }
    for (Principal principal : principals) {
      addPrincipal(principal);
    }
  }

  /**
   * Remove a principal from this group.  The principal to remove must be
   * directly contained in this group (i.e. directlyContains(principal) must
   * return true for the provided principal.
   *
   * @param principal the principal to remove
   * @return true on success; false if this group does not directly contain
   * the given principal
   */
  public boolean removePrincipal(Principal principal) {
    if (!directlyContains(principal)) {
      return false;
    }
    if (principal instanceof Group) {
      groups.remove(principal.getAclPrincipal());
    } else if (principal instanceof User) {
      users.remove(principal.getAclPrincipal());
    }
    return true;
  }

  /**
   * Get a User from this Group by name.
   *
   * @param principal The principal of the User to get
   * @return the User of the specified principal that is a member of this Group, or
   *         <code>null</code> if there is no such User
   * @throws IllegalArgumentException if the name is <code>null</code> or
   *           empty
   */
  public User getUser(AclPrincipal principal) throws IllegalArgumentException {
    if (principal == null || principal.getName().length() < 1) {
      // A User must have a non-null, non-empty name
      throw new IllegalArgumentException();
    }
    User user = users.get(principal);
    if (user != null) {
      return user;
    }
    for (Group grp : groups.values()) {
      user = grp.getUser(principal);
      if (user != null) {
        return user;
      }
    }
    return user;
  }

  /**
   * Add a User to this Group by identifier. If there already is a User with this
   * name, then it is returned. If not, a new User with the specified name is
   * created and added to the Group.
   *
   * @param name The identifier of the User to add
   * @return a new User with the specified identifier, that is a direct member of this
   *         Group
   */
  public User addUser(AclPrincipal name) {
    User user = getUser(name);
    if (user == null) {
      user = new User(name);
      putUser(user);
    }
    return user;
  }

  public User addUser(User user) {
    return addUser(user.getAclPrincipal());
  }

  public User addUser(String name) {
    return addUser(new User(name));
  }

  /**
   * Get a Group from this Group by name.
   *
   * @param principal The AclPrincipal identifier of the Group to get
   * @return the Group of the specified AclPrincipal identifier that is a member of this Group, or
   *         <code>null</code> if there is no such Group
   * @throws IllegalArgumentException if the principal is <code>null</code> or
   *           empty
   */
  public Group getGroup(AclPrincipal principal) throws IllegalArgumentException {
    if (principal == null || principal.getName().length() < 1) {
      // A Group must have a non-null, non-empty name
      throw new IllegalArgumentException();
    }
    if (principal.equals(this.principal)) { return this; }
    Group group = groups.get(principal);
    if (group != null) {
      return group;
    }
    for (Group grp : groups.values()) {
      group = grp.getGroup(principal);
      if (group != null) {
        return group;
      }
    }
    return group;
  }

  /**
   * Return the unique reference to the named group in this group if it exists and is a direct
   * member of this group.
   *
   * @param principal the AclPrincipal identifier of the group to be returned
   * @return a reference to that Group if it exists and is a direct member of this group, or null if
   * no such group exists.
   */
  public Group getDirectGroup(@Nullable AclPrincipal principal) throws IllegalArgumentException {
    if (principal == null || principal.getName().length() < 1) {
      // A Group must have a non-null, non-empty name
      throw new IllegalArgumentException();
    }
    if (principal.equals(this.principal)) { return this; }
    return groups.get(principal);
  }

  /**
   * Add a Group to this Group by AclPrincipal identifier. If there already is a Group with this
   * AclPrincipal identifier, then it is returned. If not, an empty Group with the specified
   * AclPrincipal identifier is created and added to the Group.
   *
   * @param name The identifier of the Group to add
   * @return a new User with the specified identifier, that is a direct member of this Group
   */
  public Group addGroup(AclPrincipal name) {
    return addGroup(new Group(name));
  }

  public Group addGroup(String name) {
    return addGroup(new Group(name));
  }

  /**
   * Adds a group to this group and returns a canonicalized reference to the group.  Thus, all
   * references to the group from this group will be the same.
   *
   * @param group the group to be returned after being canonicalized.  Cannot be null.
   * @return a reference to the canonicalized reference to that Group.
   */
  public Group addGroup(Group group) {
    group.canonicalizeGroup(this);
    Group existingGroup = getGroup(group.getAclPrincipal());
    if (existingGroup != null) {
      existingGroup.mergeFrom(group);
    }
    if (null == getDirectGroup(group.getAclPrincipal())) {
      if (existingGroup != null) {
        putGroup(existingGroup);
      } else {
        putGroup(group);
      }
    }
    return existingGroup != null ? existingGroup : group;
  }

  void mergeFrom(Group group) {
    for (AclPrincipal name : group.users.keySet()) {
      addUser(name);
    }

    for (Group subgroup : group.groups.values()) {
      addGroup(subgroup);
    }
  }

  /**
   * Return the number of users directly contained (listed as top-level members).
   * @return the number of users directly contained (listed as top-level members).
   */
  public int getDirectUserCount() {
    return users.size();
  }

  /**
   * Return the number of groups directly contained (listed as top-level members).
   * @return the number of groups directly contained (listed as top-level members).
   */
  public int getDirectGroupCount() {
    return groups.size();
  }

  /**
   * Return all Groups contained in this group.
   * @return all Groups contained in this group.
   */
  public ImmutableList<AclPrincipal> getDirectAclPrincipalGroups() {
    return Ordering.from(new AclPrincipalComparator()).immutableSortedCopy(groups.keySet());
  }

  /**
   * Return all Users contained in this group.
   * @return all Users contained in this group.
   */
  public ImmutableList<AclPrincipal> getDirectAclPrincipalUsers() {
    return Ordering.from(new AclPrincipalComparator()).immutableSortedCopy(users.keySet());
  }

  /**
   * Return all Principal Groups contained in this group.
   * @return all Principal Groups contained in this group.
   */
  public ImmutableList<Group> getDirectGroups() {
    return ImmutableList.copyOf(groups.values());
  }

  /**
   * Return all Principal Users contained in this group.
   * @return all Principal Users contained in this group.
   */
  public ImmutableList<User> getDirectUsers() {
    return ImmutableList.copyOf(users.values());
  }


  @Override
  public boolean equals(Object o) {
    if (!(o instanceof Group)) {
      return false;
    }
    Group g = (Group) o;
    return getAclPrincipal().equals(g.getAclPrincipal()) &&
        getDirectAclPrincipalUsers().equals(g.getDirectAclPrincipalUsers()) &&
        getDirectAclPrincipalGroups().equals(g.getDirectAclPrincipalGroups());
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }

  public boolean removeGroup(AclPrincipal groupname) {
    boolean result = false;
    for (Group g : groups.values()) {
      result = g.removeGroup(groupname) || result;
    }
    Group g = groups.remove(groupname);
    result = (g != null) || result;
    return result;
  }

  public void removeAllGroups() {
    for (AclPrincipal groupname : groups.keySet()) {
      removeGroup(groupname);
    }
  }

  public void clear() {
    users.clear();
    groups.clear();
  }

  protected void putUser(User principal) {
    users.put(principal.getAclPrincipal(), principal);
  }

  protected void putGroup(Group principal) {
    groups.put(principal.getAclPrincipal(), principal);
  }

  /**
   * Replaces all internal references to users and groups with the references to those same users
   * and groups from the parameter, if they exist in that group.
   */
  private void canonicalizeGroup(Group group) {
    if (principal.equals(group.getAclPrincipal())) {
      throw new IllegalArgumentException();
    }
    for (User user : users.values()) {
      User canonicalUser = group.getUser(user.getAclPrincipal());
      if (canonicalUser != null) {
        putUser(canonicalUser);
      }
    }
    for (Group grp : groups.values()) {
      Group canonicalGroup = group.getGroup(grp.getAclPrincipal());
      if (canonicalGroup != null) {
        canonicalGroup.mergeFrom(grp);
        putGroup(canonicalGroup);
      }
    }
  }

}
