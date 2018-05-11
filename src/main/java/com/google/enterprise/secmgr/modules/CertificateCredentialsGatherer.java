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

import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.logmanager.LogClientParameters;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.CredentialsGatherer;
import com.google.enterprise.secmgr.authncontroller.CredentialsGathererElement;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.config.AuthnMechClient;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.inject.Singleton;

import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A credentials gatherer that can gather client auth credentials: client certificates.
 *
 */
@Singleton
@Immutable
public class CertificateCredentialsGatherer implements CredentialsGatherer {
  private static final Logger logger =
     Logger.getLogger(CertificateCredentialsGatherer.class.getName());
  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());


  @Inject
  private CertificateCredentialsGatherer() {
  }

  @Override
  public boolean willHandle(SessionView view) {
    return view.getMechanism() instanceof AuthnMechClient
        && view.isIndeterminate();
  }

  @Override
  public boolean startGathering(CredentialsGathererElement element, HttpServletRequest request,
      HttpServletResponse response) {
    SessionView view = element.getSessionView();
    String namespace = view.getCredentialGroup().getName();
    Object o = request.getAttribute("javax.servlet.request.X509Certificate");
    if (o == null) {
      logger.info(view.logMessage("No client certificate."));
      gsaLogger.log(view.getRequestId(), "No client certificate was found for this user.");
      return false;
    }

    X509Certificate certs[] = (X509Certificate[]) o;
    if (certs.length < 1) {
      logger.info(view.logMessage("No client certificate."));
      gsaLogger.log(view.getRequestId(), "No client certificate was found for this user.");
      return false;
    }

    // Get the Distinguished Name for the user.
    String dn = certs[0].getSubjectX500Principal().getName();
    String idToLog = LogClientParameters.recordUsernames ? dn : LogClientParameters.ID_NOT_LOGGED;
    logger.info(view.logMessage("Got certificate DN " + idToLog));
    gsaLogger.log(view.getRequestId(), "Got certificate DN: " + idToLog);

    // Tomcat should have verified it's issued by a trusted CA, not expired by now.
    element.addSessionState(
        AuthnSessionState.of(view.getAuthority(),
            Verification.verified(
                certs[0].getNotAfter().getTime(),
                AuthnPrincipal.make(dn, namespace))));
    return false;
  }

  @Override
  public boolean continueGathering(CredentialsGathererElement element, HttpServletRequest request,
      HttpServletResponse response) {
    return false;
  }
}
