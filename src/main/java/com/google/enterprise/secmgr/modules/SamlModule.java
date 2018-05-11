// Copyright 2010 Google Inc.
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

import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.enterprise.secmgr.config.FlexAuthzRule.ParamName;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.saml.Group;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.saml.SecmgrCredential;
import com.google.inject.Singleton;

import org.opensaml.xml.security.SecurityException;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * A module that implements authorization support for SAML clients.
 */
@Singleton
@Immutable
public final class SamlModule implements AuthzModule {
  private static final Logger logger = Logger.getLogger(SamlModule.class.getName());

  @Inject
  private SamlModule() {
  }

  @Override
  public AuthzResult authorize(Collection<Resource> resources, SessionView view,
      FlexAuthzRule rule)
      throws IOException {
    Collection<String> urls = Resource.resourcesToUrls(resources);
    AuthnPrincipal principal = view.getVerifiedPrincipal();
    if (principal == null) {
      logger.warning(view.logMessage("SAML authz called without verified principal: %s", view));
      return AuthzResult.makeIndeterminate(urls);
    }

    String peerEntityId;
    try {
      peerEntityId = rule.requiredStringParam(ParamName.SAML_ENTITY_ID);
    } catch (IllegalArgumentException e) {
      // Unknown entity ID.
      logger.warning(view.logMessage("%s", e.getMessage()));
      return AuthzResult.makeIndeterminate(urls);
    }
    SamlAuthzClient samlClient
        = SamlAuthzClient.make(
            Metadata.getUnspecializedInstance(),  // We won't use the URLs.
            peerEntityId,
            SamlSharedData.getProductionInstance(SamlSharedData.Role.AUTHZ_CLIENT));
    SamlAuthzClient.Protocol protocol
        = rule.requiredBooleanParam(ParamName.SAML_USE_BATCHED_REQUESTS)
        ? SamlAuthzClient.Protocol.BATCH_V1
        : SamlAuthzClient.Protocol.STANDARD;
    Decorator decorator = view.getLogDecorator();
    int timeout = rule.hasTimeout() ? rule.getTimeout() : -1;
    try {
      List<Group> samlGroups =
          OpenSamlUtil.makeSamlGroupsFromIdentityGroups(view.getVerifiedGroups());
      if (!view.hasVerifiedPassword()) {
        logger.fine("view has no verified password");
      }
      SecmgrCredential cred = OpenSamlUtil.makeSecmgrCredential(
          principal.getName(),
          principal.getNamespace(),
          principal.getDomain(),
          view.hasVerifiedPassword() ? view.getVerifiedPassword().getText() : null,
          samlGroups);
      return samlClient.sendAuthzRequest(protocol, urls, cred, decorator, timeout);
    } catch (SecurityException e) {
      logger.warning(view.logMessage(e.getMessage()));
      return AuthzResult.makeIndeterminate(urls);
    }
  }
}
