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

import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.enterprise.supergsa.security.Domain;

/**
 * User is the simple form of Principal: a single named entity.
 */
public class User implements Principal {

  private AclPrincipal principal;
  private static final String DEFAULT_NAMESPACE = "Default";

  @SuppressWarnings("unused")
  private User() {
    throw new IllegalArgumentException();
    // prevents use of the default constructor
  }

  /**
   * Contruct a User from the given name, default namesapce and no domain set.
   * 
   * @param name The User's name.  
   * @throws IllegalArgumentException if the name is <code>null</code> or empty
   */
  public User(final String name) throws IllegalArgumentException {
    if (name == null || name.length() < 1) {
      // A User must have a non-null, non-empty name
      throw new IllegalArgumentException();
    }
    principal = AclPrincipal.newBuilder()
        .setName(name)
        .setScope(AclPrincipal.SCOPE.USER)
        .setNameSpace(DEFAULT_NAMESPACE)
        .setCaseSensitive(AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE)
        .build();
  }

  /**
   * Contruct a User from the given name, namespace and domain.
   * 
   * @param name The User's name.  
   * @param namespace The User's namespace.  
   * @param domain The User's domain.  
   * @throws IllegalArgumentException if the name is <code>null</code> or empty string.
   */
  public User(final String name, final String namespace, final Domain domain)
      throws IllegalArgumentException {
    if (name == null || name.isEmpty()) {
      // A User must have a non-null, non-empty name
      throw new IllegalArgumentException();
    }
    AclPrincipal.Builder builder = AclPrincipal.newBuilder();
    builder.setName(name);
    builder.setScope(AclPrincipal.SCOPE.USER);
    if (namespace == null && namespace.isEmpty()) {
      builder.setNameSpace(DEFAULT_NAMESPACE);
    }
    builder.setNameSpace(namespace);
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
  }

  /**
   * Construct a User from the given Principal
   *
   * @param principal The AclPrincipal identifying the User .
   * @throws IllegalArgumentException if the name in the AclPrincipal is
   * <code>null</code> or empty
   */
  public User(final AclPrincipal principal) throws IllegalArgumentException {
    if (principal == null || principal.getName().length() < 1) {
      // A User must have a non-null, non-empty name
      throw new IllegalArgumentException();
    }
    if (principal.getScope() != AclPrincipal.SCOPE.USER) {
      throw new IllegalArgumentException();
    }
    this.principal = AclPrincipal.newBuilder().mergeFrom(principal).build();
  }


  /**
   * Returns true if this User <code>equals</code> the parameter
   * Principal. Note: two different User instances with the same name do not
   * contain each other. A User only contains itself. A user can not contain a
   * Group.
   * 
   * @param principal the Principal that may be a member of this Principal
   * @return true if this Principal <code>equals</code> the parameter
   * Principal
   */
  public boolean contains(AclPrincipal principal) {
    return this.principal.equals(principal);
  }

  /**
   * Returns the Principal's AclPrincipal, which may be <code>null</code>.
   * 
   * @return the Principal's AclPrincipal
   */
  @Override
  public AclPrincipal getAclPrincipal() {
    return AclPrincipal.newBuilder()
        .mergeFrom(this.principal)
        .build();
  }

  /**
   * Returns a short string representation of the Principal.
   * @return a short string representation of the Principal.
   */
  public String getShortString() {
    return toSerializedString();
  }

  /**
   * Returns a string representation of the Principal.
   * @return a string representation of the Principal.
   */
  @Override
  public String toString() {
    return principal.toString();
  }

  public String toSerializedString() {
    return "user:" + principal.getName();
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof User)) {
      return false;
    }
    User u = (User) o;
    return principal.equals(u.principal);
  }

  @Override
  public int hashCode() {
    return toString().hashCode();
  }
}
