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

import static com.google.enterprise.secmgr.saml.OpenSamlUtil.GOOGLE_PROVIDER_NAME;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAuthnRequest;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runEncoder;
import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;

import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.servlets.SamlServlet;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.joda.time.DateTime;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLSelfEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.springframework.mock.web.MockServletConfig;

/**
 * The MockServiceProvider class implements a servlet pretending to be the part
 * of a SAML Service Provider that receives a service request from a user agent
 * and initiates an authn request to an identity provider.
 * (i.e. this is a mock for the GSA.)
 *
 * If an incoming request has a security manager cookie that indicates an
 * authenticated session state, it is granted access to the content.  The mock
 * will also immediately invalidate the authentication state, which mocks the
 * short-time-frame expiration of the assertion.
 */

public class MockServiceProvider extends SamlServlet implements GettableHttpServlet {
  private static final long serialVersionUID = 1L;

  public MockServiceProvider(SamlSharedData sharedData)
      throws ServletException {
    super(sharedData);
    init(new MockServletConfig());
  }

  @Override
  public void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws IOException {
    HttpSession session = req.getSession();

    // MockArtifactConsumer sets a flag with the authentication decision.
    // Read that flag and dispatch on its value.
    String isAuthenticated = String.class.cast(session.getAttribute("isAuthenticated"));
    // Invalidate the attribute (simulating the short artifact expiration time).
    // This allows a 2nd request from the same user agent to be forwarded to
    // the security manager again for re-validation.
    session.removeAttribute("isAuthenticated");
    if (isAuthenticated == null) {
      ifUnknown(req, resp);
    } else if ("yes".equals(isAuthenticated)) {
      positiveResponse(resp);
    } else if ("no".equals(isAuthenticated)) {
      negativeResponse(resp);
    } else {
      errorResponse(resp);
    }
  }

  static void positiveResponse(HttpServletResponse response)
      throws IOException {
    PrintWriter out = initNormalResponse(response);
    out.print("<html><head><title>What you need</title></head>"
        + "<body><h1>What you need...</h1><p>...is what we've got!</p></body></html>");
    out.close();
  }

  static void negativeResponse(HttpServletResponse response)
      throws IOException {
    initErrorResponse(response, SC_FORBIDDEN);
  }

  static void errorResponse(HttpServletResponse response)
      throws IOException {
    initErrorResponse(response, SC_INTERNAL_SERVER_ERROR);
  }

  private void ifUnknown(HttpServletRequest req, HttpServletResponse resp)
      throws IOException {
    MessageContext<SAMLObject> context = makeSamlMessageContext(req);
    initializePeerEntity(
        context,
        Metadata.getSmEntityId(),
        SingleSignOnService.DEFAULT_ELEMENT_NAME,
        SAMLConstants.SAML2_REDIRECT_BINDING_URI);

    // Generate the request
    {
      SAMLSelfEntityContext selfEntityContext =
          context.getSubcontext(SAMLSelfEntityContext.class, true);
      AuthnRequest authnRequest = makeAuthnRequest(selfEntityContext.getEntityId(), DateTime.now());
      authnRequest.setProviderName(GOOGLE_PROVIDER_NAME);
      authnRequest.setIsPassive(false);
      SPSSODescriptor sp =
          (SPSSODescriptor) context.getSubcontext(SAMLMetadataContext.class).getRoleDescriptor();
      authnRequest.setAssertionConsumerServiceIndex(
          sp.getDefaultAssertionConsumerService().getIndex());
      context.setMessage(authnRequest);
    }
    SAMLBindingSupport.setRelayState(context, HttpUtil.getRequestUrl(req, true).toString());

    // Send the request via redirect to the user agent
    initResponse(resp);
    HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
    encoder.setHttpServletResponse(resp);
    runEncoder(encoder, context, SessionUtil.getLogDecorator(req));
  }
}
