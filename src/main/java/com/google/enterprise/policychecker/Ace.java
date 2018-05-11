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

/**
 * Ace is an immutable value class that represents an Access Control Entry. An
 * Access Control Entry here is a pair: a Principal and a right.
 */
class Ace implements Comparable<Ace> {

  /**
   * Right is an enumeration of well-ordered rights.
   */
  enum Right {
    READ,
    NONE
  }

  private final Principal principal;
  private final Right right;

  @SuppressWarnings("unused")
  private Ace() {
    // disallow the default constructor
    throw new IllegalArgumentException();
  }

  /**
   * Sole public constructor: creates an Ace from a Principal and a Right
   * 
   * @param principal
   * @param right
   */
  Ace(final Principal principal, final Right right) {
    super();
    this.principal = principal;
    this.right = right;
  }

  public Principal getPrincipal() {
    return principal;
  }

  public Right getRight() {
    return right;
  }

  /**
   * Tests whether a parameter Principal has a specific Right based on this Ace
   * 
   * @param otherPrincipal the Principal to test for
   * @param r the Right to test for
   * @return true if this Ace gives this Principal the specified Right
   */
  boolean allows(final Principal otherPrincipal, final Right r) {
    return allowsAclPrincipal(otherPrincipal.getAclPrincipal(), r);
  }

  /**
   * Tests whether a parameter AclPrincipal has a specific Right based on this Ace
   * 
   * @param principal the AclPrincipal to test for
   * @param r the Right to test for
   * @return true if this Ace gives this AclPrincipal the specified Right
   */
  boolean allowsAclPrincipal(final AclPrincipal principal, final Right r) {
    if (r != right) {
      return false;
    }
    return this.principal.contains(principal);
  }

  /**
   * Returns a string representation of the Ace.
   * 
   * @return a string representation of the Ace.
   */
  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append(principal.getShortString());
    sb.append(" right=");
    sb.append(right.toString().toLowerCase());
    return sb.toString();
  }

  /**
   * Translate a String to a Right. At present, the String "read" translates to
   * Right.READ; all other Strings translate to Right.NONE
   * 
   * @param rightName the String to translate
   * @return a Right
   */
  static Right toRight(String rightName) {
    if ("read".equals(rightName)) {
      return Right.READ;
    }
    return Right.NONE;
  }

  /**
   * Returns a hash code value for the Ace. Since Aces are immutable and based
   * on a Principal and a Right, we compose their hash codes in the standard
   * way.
   * 
   * @return a hash code
   */
  @Override
  public int hashCode() {
    final int PRIME = 31;
    int result = 1;
    result = PRIME * result + ((principal == null) ? 0 : principal.hashCode());
    result = PRIME * result + ((right == null) ? 0 : right.hashCode());
    return result;
  }

  /**
   * Indicates whether some other object is "equal to" this one. Comparison is
   * component-wise (Principal and Right)
   * 
   * @param obj the reference object with which to compare.
   * @return true if the two objects are Aces and their Principals and Rights
   *         are equal.
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    final Ace other = (Ace) obj;
    return (this.principal == other.principal && this.right == other.right);
  }

  /**
   * Compares this Ace with the specified Ace for order. Comparison is based on
   * String.compareTo() on the type names (Group comes before User), then
   * String.compareTo() on the Principal name, then the enumeration order on
   * Right.
   */
  public int compareTo(final Ace other) {
    if (this.principal.getClass() != other.principal.getClass()) {
      String thisPrincipalClassName = this.principal.getClass().getName();
      String otherPrincipalClassName = other.principal.getClass().getName();
      return thisPrincipalClassName.compareTo(otherPrincipalClassName);
    }
    AclPrincipalComparator comparator = new AclPrincipalComparator();
    int diff = comparator.compare(
        this.principal.getAclPrincipal(), other.principal.getAclPrincipal());
    if (diff != 0) {
      return diff;
    }
    return this.right.compareTo(other.right);
  }
}
