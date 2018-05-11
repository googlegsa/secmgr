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

package com.google.enterprise.secmgr.identity;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.enterprise.secmgr.common.Stringify;
import com.google.enterprise.secmgr.config.CredentialTypeName;
import com.google.enterprise.secmgr.json.ProxyTypeAdapter;
import com.google.enterprise.secmgr.json.TypeAdapters;
import com.google.enterprise.secmgr.json.TypeProxy;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * A credential that contains a set of authentication group memberships
 * (such as a list of LDAP groups) to which the subject belongs.
 *
 * Similar to principals, the presence of a GroupMemberships instance does not
 * imply the credential has been verified; that is true only if the identity
 * has a verification that explicitly includes this GroupMemberships.
 * @see Verification
 */
@Immutable
@ParametersAreNonnullByDefault
public final class GroupMemberships extends AbstractCredential {

  @Nonnull private final ImmutableSet<Group> groups;
  
  private GroupMemberships(ImmutableSet<Group> groups) {
    super();
    this.groups = groups;
  }

  /**
   * Makes a groups-membership set.
   *
   * @param groups Some group names.
   * @return An instance with the given names.
   */
  @Nonnull
  public static GroupMemberships make(Iterable<Group> groups) {
    ImmutableSet<Group> groupSet = ImmutableSet.copyOf(groups);
    Preconditions.checkArgument(!groupSet.isEmpty());
    return new GroupMemberships(groupSet);
  }

  /**
   * Makes a groups-membership set that merges some group names with a previous
   * set.
   *
   * @param groups Some group names.
   * @param other Another groups-membership set to merge.
   * @return An instance with the given names.
   */
  @Nonnull
  public static GroupMemberships make(Iterable<Group> groups, GroupMemberships other) {
    Preconditions.checkArgument(!Iterables.isEmpty(groups));
    return new GroupMemberships(
        ImmutableSet.<Group>builder()
        .addAll(other.getGroups())
        .addAll(groups)
        .build());
  }

  /**
   * Gets a set of the contained group names.
   *
   * @return The group's names as an immutable set of strings.
   */
  @Nonnull
  public ImmutableSet<Group> getGroups() {
    return groups;
  }

  @Override
  public boolean isPublic() {
    return true;
  }

  @Override
  public CredentialTypeName getTypeName() {
    return CredentialTypeName.GROUPS;
  }

  @Override
  public boolean isVerifiable() {
    return true;
  }

  @Override
  public boolean equals(Object object) {
    if (object == this) { return true; }
    if (!(object instanceof GroupMemberships)) { return false; }
    GroupMemberships g = (GroupMemberships) object;
    return Objects.equals(groups, g.getGroups());
  }

  @Override
  public int hashCode() {
    return Objects.hash(groups);
  }

  @Override
  public String toString() {
    return "{groups: " + Stringify.objects(groups) + "}";
  }

  static void registerTypeAdapters(GsonBuilder builder) {
    builder.registerTypeAdapter(GroupMemberships.class,
        ProxyTypeAdapter.make(GroupMemberships.class, LocalProxy.class));
    builder.registerTypeAdapter(new TypeToken<ImmutableSet<Group>>() {}.getType(),
        TypeAdapters.immutableSet());
  }

  private static final class LocalProxy implements TypeProxy<GroupMemberships> {
    ImmutableSet<Group> groups;

    @SuppressWarnings("unused")
    LocalProxy() {
    }

    @SuppressWarnings("unused")
    LocalProxy(GroupMemberships credential) {
      groups = credential.getGroups();
    }

    @Override
    public GroupMemberships build() {
      return make(groups);
    }
  }
}
