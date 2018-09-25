// Copyright 2014 Google Inc.
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

package com.google.enterprise.secmgr.mock;

import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.saml.SecmgrCredential;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * An authorization method by matching the credential with Acl.
 */
public class AuthorizeByAcl implements AuthorizeWithCredential {
  private final Map<String, Acl> aclMap;

  public AuthorizeByAcl(Map<String, Acl> aclMap) {
    this.aclMap = aclMap;
  }

  @Override
  public AuthzResult authorize(Collection<Resource> resources, SecmgrCredential cred) {
    AuthzResult.Builder builder = AuthzResult.builder(
        Resource.resourcesToUrls(resources));
    for (Resource resource : resources) {
      String url = resource.getUrl();
      Acl acl = aclMap.get(url);
      if (acl == null) {
        builder.put(url, AuthzStatus.DENY);
      } else {
        builder.put(url, acl.isAuthorized(cred));
      }
    }
    return builder.build();
  }

  /**
   * An oversimplified implementation of Acl used in Authz.
   *
   * No inheritance.
   * Just permit group. (will DENY if not in permit groups and users)
   * Permit groups can NOT be null.
   * Group matching is case sensitive.
   */
  public static final class Acl {
    private Set<Group> permitGroups;

    private Acl(Set<Group> permitGroups) {
      this.permitGroups = permitGroups;
    }

    public AuthzStatus isAuthorized(SecmgrCredential cred) {
      // We can not override equals method for saml.Group, so we need to get identity.Group first.
      Set<Group> userGroups = getIdentityGroupFromCredential(cred);
      Set<Group> commonGroups = new HashSet<Group>(permitGroups);
      commonGroups.retainAll(userGroups);
      if (!commonGroups.isEmpty()) {
        return AuthzStatus.PERMIT;
      }
      return AuthzStatus.DENY;
    }

    private static Set<Group> getIdentityGroupFromCredential(SecmgrCredential cred) {
      Set<Group> identityGroups = new HashSet<Group>();
      for (com.google.enterprise.secmgr.saml.Group group : cred.getGroups()) {
        identityGroups.add(Group.make(group.getName(), group.getNamespace(), group.getDomain()));
      }
      return identityGroups;
    }

    public static class Builder {
      private Set<Group> permitGroups = Collections.emptySet();

      public Builder() {}

      public Acl build() {
        return new Acl(permitGroups);
      }

      public Builder setPermitGroups(Collection<Group> permitGroups) {
        this.permitGroups = Collections.unmodifiableSet(new HashSet<Group>(permitGroups));
        return this;
      }
    }
  }
}
