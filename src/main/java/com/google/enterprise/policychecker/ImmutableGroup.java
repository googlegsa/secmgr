// Copyright 2012 Google Inc. All Rights Reserved.
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
import com.google.enterprise.supergsa.security.AclPrincipal;

import java.util.Collection;

/**
 * An Immutable version of Group, where all state-changing operations throw
 * UnsupportedOperationExceptions.
 *
 */
public class ImmutableGroup extends Group {

  private final Group group;

  public ImmutableGroup(Group group) {
    super(group.getAclPrincipal());
    this.group = group;
  }

  public ImmutableGroup(String name) {
    super(name);
    this.group = new Group(name);
  }

  public ImmutableGroup(AclPrincipal principal) {
    super(principal);
    this.group = new Group(principal);
  }

  @Override
  public ImmutableList<AclPrincipal> getUsers() {
    return group.getUsers();
  }

  @Override
  public ImmutableList<AclPrincipal> getGroups() {
    return group.getGroups();
  }

  @Override
  public boolean contains(AclPrincipal principal) {
    return group.contains(principal);
  }

  @Override
  public boolean directlyContains(Principal principal) throws IllegalArgumentException {
    return group.directlyContains(principal);
  }

  @Override
  public User getUser(AclPrincipal name) throws IllegalArgumentException {
    return group.getUser(name);
  }

  @Override
  public Group getGroup(AclPrincipal name) throws IllegalArgumentException {
    return group.getGroup(name);
  }

  @Override
  public Group getDirectGroup(AclPrincipal name) throws IllegalArgumentException {
    return group.getDirectGroup(name);
  }

  @Override
  public int getDirectUserCount() {
    return group.getDirectUserCount();
  }

  @Override
  public int getDirectGroupCount() {
    return group.getDirectGroupCount();
  }

  @Override
  public ImmutableList<AclPrincipal> getDirectAclPrincipalUsers() {
    return group.getDirectAclPrincipalUsers();
  }

  @Override
  public ImmutableList<AclPrincipal> getDirectAclPrincipalGroups() {
    return group.getDirectAclPrincipalGroups();
  }

  @Override
  public String toString() {
    return group.toString();
  }

  @Override
  public String toSerializedString() {
    return group.toSerializedString();
  }

  @Override
  public String dumpToString() {
    return group.dumpToString();
  }

  @Override
  protected void mergeFrom(Group group) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Principal addPrincipal(Principal principal) throws IllegalArgumentException {
    throw new UnsupportedOperationException();
  }

  @Override
  public void addPrincipals(final Collection<Principal> principals) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean removePrincipal(Principal principal) {
    throw new UnsupportedOperationException();
  }

  @Override
  public User addUser(AclPrincipal name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public User addUser(User user) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Group addGroup(AclPrincipal name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Group addGroup(Group group) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean removeGroup(AclPrincipal groupname) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void removeAllGroups() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void clear() {
    throw new UnsupportedOperationException();
  }

  @Override
  protected void putUser(User principal) {
    throw new UnsupportedOperationException();
  }

  @Override
  protected void putGroup(Group principal) {
    throw new UnsupportedOperationException();
  }

}
