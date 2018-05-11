// Copyright 2011 Google Inc.
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

package com.google.enterprise.secmgr.modules;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableSet;
import com.google.enterprise.policychecker.AclUtil;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.inject.Singleton;

import java.io.IOException;
import java.util.Collection;
import java.util.logging.Logger;

import javax.inject.Inject;

/**
 * Authorization module for Per Url Acls.
 *
 */

@Singleton
public class PerUrlAclModule implements AuthzModule {
  private static final Logger logger = Logger.getLogger(PerUrlAclModule.class.getName());

  @Inject
  @VisibleForTesting
  PerUrlAclModule() {
  }

  @Override
  public AuthzResult authorize(Collection<Resource> resources, SessionView view,
      FlexAuthzRule rule) {
    Collection<String> urls = Resource.resourcesToUrls(resources);
    boolean lateBinding;
    try {
      lateBinding = ConfigSingleton.getLateBindingAcl();
    } catch (IOException e) {
      logger.warning("Failed to get the secmgr config.");
      lateBinding = false;
    }

    AuthzResult.Builder builder = AuthzResult.builder(urls);
    for (Resource resource : resources) {
      String url = resource.getUrl();
      // Copy ACL results provided by the index to Flex AuthZ's result.
      AuthzStatus priorAclDecision = resource.getPriorAclDecision();
      AuthzStatus status = AuthzStatus.INDETERMINATE;
      if (priorAclDecision != null) {
        if (lateBinding) {
          status = getLateBindingStatus(priorAclDecision);
        } else {
          status = priorAclDecision;
        }
      }
      builder.put(url, status);
    }
    return builder.build();
  }

  private AuthzStatus getLateBindingStatus(AuthzStatus status) {
    if (status == AuthzStatus.PERMIT) {
      status = AuthzStatus.INDETERMINATE;
    }
    return status;
  }
}
