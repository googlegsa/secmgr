// Copyright 2009 Google Inc.
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

import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.secmgr.authncontroller.CredentialsGatherer;
import com.google.enterprise.secmgr.authncontroller.CredentialsGathererElement;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.config.AuthnMechSaml;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.inject.Singleton;

import java.io.IOException;

import java.net.URI;
import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A credentials gatherer that implements authentication for SAML clients.
 */
@Singleton
@Immutable
public class SamlCredentialsGatherer implements CredentialsGatherer {

  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());

  @Inject
  private SamlCredentialsGatherer() {
  }

  @Override
  public boolean willHandle(SessionView view) {
    return view.getMechanism() instanceof AuthnMechSaml
        && view.isIndeterminate();
  }

  @Override
  public boolean startGathering(CredentialsGathererElement element, HttpServletRequest request,
      HttpServletResponse response)
      throws IOException {
    SessionView view = element.getSessionView();
    AuthnMechSaml mech = (AuthnMechSaml) view.getMechanism();
    URI uri = HttpUtil.getRequestUri(request, false);
    SamlAuthnClient client
        = SamlAuthnClient.make(Metadata.getInstance(uri), mech.getEntityId(),
            SamlSharedData.getProductionInstance(SamlSharedData.Role.SERVICE_PROVIDER),
            mech.getTimeout(),
            uri);
    gsaLogger.info(view.getRequestId(), "SAML Authn: sending authentication request"
        + " to service provider at Entity ID: " + mech.getEntityId());
    // Save the client for use when consuming assertion.
    element.setPrivateState(client);
    client.sendAuthnRequest(response, view.getLogDecorator());
    return true;
  }

  @Override
  public boolean continueGathering(CredentialsGathererElement element, HttpServletRequest request,
      HttpServletResponse response) {
    return false;
  }
}
