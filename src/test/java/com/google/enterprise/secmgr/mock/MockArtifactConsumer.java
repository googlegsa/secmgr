// Copyright 2008 Google Inc.
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

import static com.google.enterprise.secmgr.saml.OpenSamlUtil.isAuthnFailureStatus;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.isSecurityFailureStatus;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.isSuccessfulStatus;

import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.modules.SamlAuthnClient;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.SamlLogUtil;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.servlets.ResponseParser;
import com.google.enterprise.secmgr.servlets.SamlServlet;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;

/**
 * The MockArtifactConsumer class implements a servlet pretending to be the part of a SAML Service
 * Provider that receives a service request from the user agent and initiates an authn request from
 * an identity provider.
 */
public class MockArtifactConsumer extends SamlServlet implements GettableHttpServlet {

  /** Required for serializable classes. */
  private static final long serialVersionUID = 1L;
  private static final Logger LOGGER = Logger.getLogger(MockArtifactConsumer.class.getName());

  public MockArtifactConsumer(SamlSharedData sharedData) {
    super(sharedData);
  }

  @Override
  public void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws IOException {
    HttpSession session = req.getSession();
    Decorator decorator = SessionUtil.getLogDecorator(req);

    SamlAuthnClient client
        = SamlAuthnClient.make(Metadata.getInstance(req), Metadata.getSmEntityId(),
            getSharedData());

    // Always respond with redirect.
    initResponse(resp);
    resp.sendRedirect(req.getParameter("RelayState"));

    Response response;
    try {
      response = client.decodeResponse(req, SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
    } catch (MessageHandlerException e) {
      LOGGER.log(Level.WARNING, decorator.apply("ArtifactResponse failed authentication: "), e);
      session.setAttribute("isAuthenticated", "no");
      return;
    } catch (IOException e) {
      LOGGER.warning(decorator.apply("Error from artifact resolver: " + e.getMessage()));
      session.setAttribute("isAuthenticated", "error");
      return;
    }
    Status status = response.getStatus();
    LOGGER.info(SamlLogUtil.xmlMessage(decorator.apply("status"), status));
    if (isSuccessfulStatus(status)) {
      extractSessionStateFromAssertion(session, response.getAssertions().get(0));
    } else if (isAuthnFailureStatus(status) || isSecurityFailureStatus(status)) {
      session.setAttribute("isAuthenticated", "no");
    } else {
      session.setAttribute("isAuthenticated", "error");
    }
  }

  /**
   * This method approximates how the GSA parses a SAML identity assertion
   * @throws IOException
   */
  private void extractSessionStateFromAssertion(HttpSession session, Assertion assertion)
      throws IOException {
    // these attributes are set in the HttpSession for convenience - so that the test context
    // can pick them up and assert on them
    session.setAttribute("isAuthenticated", "yes");
    session.setAttribute("verifiedIdentity", assertion.getSubject().getNameID().getValue());
    session.setAttribute("verificationStatement",
        assertion.getStatements(AuthnStatement.DEFAULT_ELEMENT_NAME).get(0));
    session.setAttribute("exportedState", ResponseParser.getExportedState(assertion));
    session.setAttribute("expirationTime", assertion.getConditions().getNotOnOrAfter().getMillis());
  }
}
