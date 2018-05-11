/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.enterprise.policychecker;

import com.google.common.base.Preconditions;
import com.google.common.collect.Interner;
import com.google.common.collect.Interners;
import com.google.common.collect.Sets;
import com.google.enterprise.supergsa.security.AclGroup;
import com.google.enterprise.supergsa.security.AclPrincipal;

import java.util.AbstractMap;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Class used to store groups and their members.
 */

public class GroupMembersMap extends AbstractMap<AclPrincipal, Set<AclPrincipal>>{

  protected GroupMembersMap(Map<AclPrincipal, Set<AclPrincipal>> groups) {
    this.map = groups;
  }

  /**
   * Simple builder class to add group/users associations and
   * build from {@link InputRecordStream} objects.
   */
  public static class Builder {

    public Builder() {
      map = new HashMap<AclPrincipal, Set<AclPrincipal>>();
    }

    /**
     * Builds the {@link GroupMembersMap} and returns it.  Note that doing things to the
     * builder after calling {@code build()} will modifying the underlying map.  Be careful
     * with what you are doing here.  In most cases it's probably better to chain the
     * constructor together with all modifiers and a call to {@code build()}.  See the unittest
     * for more details.
     */
    public GroupMembersMap build() {
      return new GroupMembersMap(map);
    }

    /**
     * Puts the group into the map. If the group already exists, it will replace previous one.
     */
    public Builder put(AclGroup group) {
      AclPrincipal principal = group.getPrincipal();
      Preconditions.checkNotNull(principal);
      Preconditions.checkArgument(principal.getScope() == AclPrincipal.SCOPE.GROUP);

      // If the group exists already, we replace old group with new group member information.
      map.remove(principal);

      if (group.getMembersCount() == 0) {
        return this;
      }

      principal = interner.intern(principal);
      Set<AclPrincipal> members = Sets.newHashSet();
      map.put(principal, members);

      for (AclPrincipal member : group.getMembersList()) {
        Preconditions.checkNotNull(member);
        member = interner.intern(member);
        members.add(member);
      }
      return this;
    }

    private HashMap<AclPrincipal, Set<AclPrincipal>> map;
    private Interner<AclPrincipal> interner = Interners.newStrongInterner();
  }

  public static Builder builder() {
    return new Builder();
  }
  
  @Override
  public Set<Map.Entry<AclPrincipal, Set<AclPrincipal>>> entrySet() {
    return Collections.unmodifiableSet(map.entrySet());
  }
  
  private Map<AclPrincipal, Set<AclPrincipal>> map;
}
