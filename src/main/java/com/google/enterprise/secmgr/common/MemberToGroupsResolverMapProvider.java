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
import com.google.enterprise.policychecker.AclConfigurationStore;

/**
 * A simple provider for a MemberToGroupsResolverMap instance. Implements method for loading and
 * generating MemberToGroupsResolverMap instance by calling regenerateMemberToGroupsMap.
 */
public class MemberToGroupsResolverMapProvider {

  private volatile MemberToGroupsResolverMap memberGroupMap;

  public MemberToGroupsResolverMapProvider() {
    memberGroupMap = null;
  }

  public MemberToGroupsResolverMap getResolver() {
    return memberGroupMap;
  }

  /**
   * Re-reads the groups from disk and generates the MemberToGroupsResolverMap.
   */
  public void regenerateMemberToGroupsMap(AclConfigurationStore store) {
    Preconditions.checkNotNull(store);
    memberGroupMap = MemberToGroupsResolverMap.builder()
        .merge(store.readGroupsIntoMap())
        .build();
  }
}
