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

import com.google.common.base.Strings;
import com.google.common.collect.Multimap;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.saml.SecmgrCredential;

import java.util.Collection;
import java.util.Map;

/**
 * An authorization method by first authenticating user and then checking whether the authn-ed user
 * has permission to a resource.
 *
 * This is essentially mocking file system adaptor's case, where the adaptor will impersonate the
 * user and the file system will decide whether the user is permitted or denied.
 */
public class AuthorizeByThirdParty implements AuthorizeWithCredential {
  private final Map<String, String> usernamePasswordMap;
  private final Multimap<String, String> authorizationMap;

  public AuthorizeByThirdParty(Map<String, String> usernamePasswordMap,
      Multimap<String, String> authorizationMap) {
    this.usernamePasswordMap = usernamePasswordMap;
    this.authorizationMap = authorizationMap;
  }

  @Override
  public AuthzResult authorize(Collection<Resource> resources, SecmgrCredential cred) {
    String username = cred.getName();
    String domain = cred.getDomain();
    String fullUsername = username;
    if (!Strings.isNullOrEmpty(domain)) {
      fullUsername = domain + "\\" + username;
    }
    String password = cred.getPassword();

    boolean authenticated = usernamePasswordMap.containsKey(fullUsername);
    Collection<String> authorizedResources = null;
    if (authenticated) {
      String goldenPassword = usernamePasswordMap.get(fullUsername);
      authenticated = !((password == null) ^ (goldenPassword == null));
      if (authenticated && password != null) {
        authenticated = password.equals(goldenPassword);
      }
    }
    if (authenticated) {
      authorizedResources = authorizationMap.get(fullUsername);
    }

    AuthzResult.Builder builder = AuthzResult.builder(
        Resource.resourcesToUrls(resources));
    for (Resource resource : resources) {
      if (!authenticated) {
        builder.put(resource.getUrl(), AuthzStatus.DENY);
      } else {
        builder.put(resource.getUrl(),
            authorizedResources.contains(resource.getUrl())
            ? AuthzStatus.PERMIT
            : AuthzStatus.DENY);
      }
    }
    return builder.build();
  }
}
