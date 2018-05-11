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
import com.google.common.collect.Lists;
import com.google.enterprise.policychecker.Ace.Right;
import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.enterprise.supergsa.security.GsaAcl;
import com.google.enterprise.supergsa.security.GsaAclEntry;
import com.google.enterprise.supergsa.security.GsaEntry;

import java.util.Collection;
import java.util.List;
import java.util.TreeSet;

/**
 * Acl is an immutable value class that represents an Access Control List.
 * An Access Control List here is simply a list of {@link Ace}s.
 * <p>
 * The signature of a Acl is created by putting the list in order by Ace,
 * according to natural {@link Ace#compareTo(Ace)} ordering.
 * <p>
 * Acls are immutable so that they can be canonicalized and compared with
 * one another. In a working system, it is expected that Acls will be stored in
 * an associative structure such as a HashMap, keyed on their signatures, so
 * that there will be no more than one instance of an Acl in an equivalence
 * class.
 */
public class Acl implements Comparable<Acl> {

  // We use a TreeSet here so that the Aces are put in canonical sorted order
  private final TreeSet<Ace> aces;
  private final String signature;

  private static final Acl EMPTY_ACL = new Acl(new TreeSet<Ace>());

  /**
   * Convenience method for building a Acl from a GsaAcl protocol buffer.
   * @param acl ACL protocol buffer describing ACL to return
   * @param group Group database with which to canonicalize Aces in the ACL so references are
   * consistent.
   */
  public static Acl fromGsaAcl(GsaAcl acl, Group group) {
    if (acl.getEntriesCount() == 0) {
      return null;
    }
    List<Ace> aces = Lists.newArrayList();
    for (GsaAclEntry entry : acl.getEntriesList()) {
      if (entry.hasGsaEntry()) {
        aces.add(processGsaEntry(entry.getGsaEntry(), group));
      }
    }
    return new Acl(aces);
  }

  public static Acl fromGsaAcl(GsaAcl acl) {
    return fromGsaAcl(acl, null);
  }

  public static Acl emptyAcl() {
    return EMPTY_ACL;
  }

  // Build a GsaAcl from this Acl.  Each Ace maps onto a GsaEntry as defined in
  // enterprise/supergsa/security/acl.proto.
  public GsaAcl toGsaAcl() {
    GsaAcl.Builder acl = GsaAcl.newBuilder();
    for (Ace ace : aces) {
      GsaAclEntry.Builder aclEntry = acl.addEntriesBuilder();
      GsaEntry.Builder entryBuilder = aclEntry.getGsaEntryBuilder();
      entryBuilder.mergePrincipal(ace.getPrincipal().getAclPrincipal());
      if (ace.getRight() == Ace.Right.READ) {
        entryBuilder.setAccess(GsaEntry.ACCESS.PERMIT);
      } else {
        entryBuilder.setAccess(GsaEntry.ACCESS.DENY);
      }
      entryBuilder.build();
      aclEntry.build();
    }
    return acl.build();
  }

  /**
   * Handy {@code Comparator<Acl>}-style static function that can be used to build
   * compareTo's or Comparators for other Acl classes. Returns a negative
   * integer, zero, or a positive integer as the first Acl is less than, equal
   * to, or greater than the second.
   * 
   * @param thisAcl
   * @param otherAcl
   * @return Returns a negative integer, zero, or a positive integer as the
   *         first Acl is less than, equal to, or greater than the second.
   */
  public static int compareAcls(final Acl thisAcl, final Acl otherAcl) {
    return thisAcl.getSignature().compareTo(otherAcl.getSignature());
  }

  private static Ace processGsaEntry(GsaEntry entry, Group group) {
    Principal p;
    Right r;
    switch (entry.getPrincipal().getScope()) {
      case USER:
        p = new User(entry.getPrincipal());
        break;
      case GROUP:
        p = new Group(entry.getPrincipal());
        break;
      default:
        throw new IllegalArgumentException(
            "Invalid scope value: " + entry.getPrincipal().getScope());
    }
    switch (entry.getAccess()) {
      case PERMIT:
        r = Right.READ;
        break;
      case DENY:
        r = Right.NONE;
        break;
      default:
        throw new IllegalArgumentException("Invalid access value: " + entry.getAccess());
    }
    // This will canonicalize the group reference if the group parameter is supplied.
    if (group != null) {
      p = group.addPrincipal(p);
    }
    return new Ace(p, r);
  }

  private static String createSignature(final Collection<Ace> sortedAces) {
    StringBuilder sb = new StringBuilder();
    String separator = "";
    for (Ace ace : sortedAces) {
      sb.append(separator);
      sb.append(ace.toString());
      separator = " ";
    }
    return sb.toString();
  }

  private Acl(final TreeSet<Ace> aces) {
    this.signature = createSignature(aces);
    this.aces = aces;
  }

  /**
   * Sole public constructor: makes an Acl from a Collection of Aces.
   * 
   * @param aces a Collection of Aces
   */
  public Acl(final Collection<Ace> aces) {
    this(new TreeSet<Ace>(aces));
  }

  /**
   * Returns a signature String unique to this Acl equivalence class. All Acls
   * equal to this will have the same signature String. All Acls not equal to
   * this will have signatures different from this one's. The caller should
   * treat this String as an opaque identifier.
   * 
   * @return a signature string representation of this Acl.
   */
  public String getSignature() {
    return signature;
  }

  public String toString() {
    return getSignature();
  }

  /**
   * Returns the identifiers for all the Aces in this ACL.
   */
  public ImmutableList<Principal> getPrincipals() {
    ImmutableList.Builder<Principal> builder = ImmutableList.builder();
    for (Ace ace : aces) {
      builder.add(ace.getPrincipal());
    }
    return builder.build();
  }

  /**
   * Returns the identifiers for all the Aces in ACL.
   */
  public ImmutableList<AclPrincipal> getAclPrincipals() {
    ImmutableList.Builder<AclPrincipal> builder = ImmutableList.builder();
    for (Ace ace : aces) {
      builder.add(ace.getPrincipal().getAclPrincipal());
    }
    return builder.build();
  }

  /**
   * Returns all the Aces in this ACL.
   */
  public ImmutableList<Ace> getAces() {
    ImmutableList.Builder<Ace> builder = ImmutableList.builder();
    builder.addAll(aces);
    return builder.build();
  }

  /**
   * Returns the identifiers for all the Aces which are users in this ACL.
   */
  public ImmutableList<AclPrincipal> getUsers() {
    ImmutableList.Builder<AclPrincipal> builder = ImmutableList.builder();
    for (Ace ace : aces) {
      Principal principal = ace.getPrincipal();
      if (principal instanceof User) {
        builder.add(principal.getAclPrincipal());
      }
    }
    return builder.build();
  }

  /**
   * Returns the identifiers for all the Aces which are groups in this ACL.
   */
  public ImmutableList<AclPrincipal> getGroups() {
    ImmutableList.Builder<AclPrincipal> builder = ImmutableList.builder();
    for (Ace ace : aces) {
      Principal principal = ace.getPrincipal();
      if (principal instanceof Group) {
        builder.add(principal.getAclPrincipal());
      }
    }
    return builder.build();
  }

  /**
   * Indicates whether some other object is "equal to" this one. Comparison
   * should be by signature only.
   * 
   * @param obj
   * @return true if the two objects are equal
   */
  public boolean equals(Object obj) {
    if (this == obj) { return true; }
    if (obj == null) { return false; }
    if (!(obj instanceof Acl)) { return false; }
    final Acl other = (Acl) obj;
    return signature.equals(other.getSignature());
  }

  /**
   * Returns a hash code value for the object. The hash code should be based
   * solely on the signature.
   * 
   * @return integer hash code
   */
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((signature == null) ? 0 : signature.hashCode());
    return result;
  }

  /**
   * Compares this Acl with the specified Acl for order. Returns a negative
   * integer, zero, or a positive integer as this Acl is less than, equal to, or
   * greater than the specified Acl. Comparison should be based solely on
   * signature.
   * 
   * @param other
   * @return a negative integer, zero, or a positive integer as this Acl is less
   *         than, equal to, or greater than the specified Acl.
   */
  public int compareTo(Acl other) {
    return compareAcls(this, other);
  }

  /**
   * Test whether this Acl allows READ privilege to a named AclPrincipal
   * 
   * @param principal a principal to test
   * @return true if the principal has READ privilege
   */
  public boolean allowsRead(AclPrincipal principal) {
    return allowsRight(principal, Right.READ);
  }
  
  /**
   * Test whether this Acl allows READ privilege to any of a list of AclPrincipals
   * 
   * @param aclPrincipals a list of principals to test
   * @return true if at least one principal has READ privilege
   */
  public boolean allowsReadToAnyAclPrincipal(List<AclPrincipal> aclPrincipals) {
    return allowsRightToAnyAclPrincipal(aclPrincipals, Right.READ);
  }

  /**
   * Test whether this Acl explicitly forbids READ privilege to a named AclPrincipal
   * 
   * @param principal a principal to test
   * @return true if the principal has READ privilege
   */
  public boolean forbidsRead(AclPrincipal principal) {
    return allowsRight(principal, Right.NONE);
  }
  
  /**
   * Test whether this Acl explicitly forbids READ privilege to any of a list of
   * AclPrincipals.
   * 
   * @param aclPrincipals a list of names of users to test
   * @return true if at least one names user has READ privilege
   */
  public boolean forbidsReadToAnyAclPrincipal(List<AclPrincipal> aclPrincipals) {
    return allowsRightToAnyAclPrincipal(aclPrincipals, Right.NONE);
  }

  private boolean allowsRight(AclPrincipal principal, Right right) {
    if (principal == null) {
      throw new IllegalArgumentException();
    }
    for (Ace ace : aces) {
      if (ace.allowsAclPrincipal(principal, right)) {
        return true;
      }
    }
    return false;
  }

  private boolean allowsRightToAnyAclPrincipal(List<AclPrincipal> aclPrincipals, Right right) {
    for (AclPrincipal principal : aclPrincipals) {
      if (allowsRight(principal, right)) {
        return true;
      }
    }
    return false;
  }
}
