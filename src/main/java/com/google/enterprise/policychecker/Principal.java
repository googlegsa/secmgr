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
 * Principal is an interface for an entity that may be given rights to a
 * resource.
 * 
 * <p>
 * There are only two concrete types that implement Principal: User and Group.
 * Care should be taken if this ever changes, because code may rely on the fact
 * that <code>o instanceof Principal</code> iff (<code>(o instanceof User)</code>
 * or <code>(o instanceof Group)</code>).
 * 
 */
public interface Principal {

  /**
   * Returns true if the parameter Principal is a member of this Principal. In
   * general, every Principal is a member of itself, and a User is a member of a
   * Group if it is directly contained in the Group, or is contained through an
   * arbitrary chain of sub-Groups.  For more details, see User and Group.
   * 
   * @param principal the Principal that may be a member of this Principal
   * @return true if the parameter is a member of this Principal
   */
  public boolean contains(AclPrincipal principal);

  /**
   * Returns the Principal's AclPrincipal identifier, which may not be <code>null</code> or empty.
   * 
   * @return the Principal's AclPrincipal identifier
   */
  public AclPrincipal getAclPrincipal();

  /**
   * Returns a short String representation of the Principal.
   * 
   * @return a short String representation of the Principal
   */
  public String getShortString();

  /**
   * Returns a plain-text description of this principal.  If this.equals(o) for some object o, then
   * this.toSerializedString().equals(o.toSerializedString()) should be true.
   * @return a short String representation of the Principal
   */
  public String toSerializedString();
}
