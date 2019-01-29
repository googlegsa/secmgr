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

package com.google.enterprise.secmgr.mock;

import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getAuthnRequestsSignedRule;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getRedirectSignatureRule;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.initializeSecurityPolicy;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeSingleSignOnService;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runDecoder;
import static org.opensaml.common.xml.SAMLConstants.SAML20P_NS;

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.servlets.ResponseGenerator;
import com.google.enterprise.secmgr.servlets.SamlArtifactResolve;
import com.google.enterprise.secmgr.servlets.SamlIdpServlet;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.security.SecurityException;

/**
 * A mock of a SAML "identity provider" server.
 */
public class MockSamlIdp extends SamlIdpServlet
    implements GettableHttpServlet, MockServer {

  private static final Logger logger = Logger.getLogger(MockSamlIdp.class.getName());

  private final Metadata metadata;
  private final String contextUrl;
  private final String destinationOverride;
  private final Function<SAMLMessageContext<AuthnRequest, Response, NameID>, ResponseGenerator>
      originalSupplier;
  private final List<String> requiredQueryParameters;
  private Function<SAMLMessageContext<AuthnRequest, Response, NameID>, ResponseGenerator> supplier;
  private AuthnSession session;

  public MockSamlIdp(SamlSharedData sharedData, String responseBinding, Metadata metadata,
      String contextUrl, String destinationOverride,
      Function<SAMLMessageContext<AuthnRequest, Response, NameID>, ResponseGenerator> supplier) {
    super(sharedData, responseBinding);
    this.metadata = metadata;
    this.contextUrl = contextUrl;
    this.destinationOverride = destinationOverride;
    this.originalSupplier = supplier;
    requiredQueryParameters = Lists.newArrayList();
    reset();
  }

  @Override
  public void addToIntegration(MockIntegration integration)
      throws IOException, ServletException {
    EntityDescriptor entity = metadata.getEntity(getLocalEntityId());
    IDPSSODescriptor idp = entity.getIDPSSODescriptor(SAML20P_NS);
    MockHttpTransport transport = integration.getHttpTransport();
    transport.registerEntity(entity, contextUrl);
    transport.registerServlet(idp.getSingleSignOnServices().get(0), this);
    Endpoint endpoint = idp.getDefaultArtifactResolutionService();
    if (endpoint != null) {
      transport.registerServlet(endpoint, new SamlArtifactResolve(getSharedData()));
    }
    if (destinationOverride != null) {
      transport.registerUrlAlias(destinationOverride,
          integration.getSamlAssertionConsumerUrl().toString());
    }
  }

  @Override
  public String getContextUrl() {
    return contextUrl;
  }

  @Override
  public String getSampleUrl() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void reset() {
    supplier = originalSupplier;
    session = null;
  }

  public Function<SAMLMessageContext<AuthnRequest, Response, NameID>, ResponseGenerator>
      getResponseGeneratorSupplier() {
    return supplier;
  }

  public void setResponseGeneratorSupplier(
      Function<SAMLMessageContext<AuthnRequest, Response, NameID>, ResponseGenerator> supplier) {
    this.supplier = supplier;
  }

  public void setConfig(SecurityManagerConfig config) {
    session = AuthnSession.newInstance(config);
  }

  public void setCredentialGroups(List<CredentialGroup> credentialGroups) {
    session = (credentialGroups != null)
        ? AuthnSession.newInstance(SecurityManagerConfig.make(credentialGroups))
        : null;
  }

  public void addVerification(AuthnAuthority authority, Verification verification) {
    session.addVerification(authority, verification);
  }

  public void addRequiredQueryParameter(String name) {
    Preconditions.checkNotNull(name);
    requiredQueryParameters.add(name);
  }

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    Decorator decorator = SessionUtil.getLogDecorator(request);

    // Generate 404 if one of the required query parameters is missing.
    Map<?, ?> params = request.getParameterMap();
    for (String name : requiredQueryParameters) {
      if (!params.containsKey(name)) {
        initErrorResponse(response, HttpServletResponse.SC_NOT_FOUND);
        return;
      }
    }

    // Establish the SAML message context.
    SAMLMessageContext<AuthnRequest, Response, NameID> context
        = makeSamlMessageContext(metadata);
    initializeSecurityPolicy(context,
        getAuthnRequestsSignedRule(),
        getRedirectSignatureRule());

    // Decode the request.
    context.setInboundMessageTransport(new HttpServletRequestAdapter(request));
    try {
      runDecoder(new RedirectDecoder(), context, decorator, AuthnRequest.DEFAULT_ELEMENT_NAME);
    } catch (IOException e) {
      failFromException(e, session, request, response);
      return;
    } catch (SecurityException e) {
      failFromException(e, session, request, response);
      return;
    }

    // Select entity for response.
    initializePeerEntity(context, AssertionConsumerService.DEFAULT_ELEMENT_NAME,
        getResponseBinding(context), getSharedData());

    Response samlResponse = supplier.apply(context).generate(
        (session != null) ? session.getSnapshot() : null);
    if (destinationOverride != null) {
      // Force the message to be sent to a different location than the one in
      // the response message.
      context.setPeerEntityEndpoint(
          makeSingleSignOnService(
              context.getPeerEntityEndpoint().getBinding(),
              destinationOverride));
    }
    logger.info("Response binding " + getResponseBinding(context)
        + " Peer endpint binding" + context.getPeerEntityEndpoint().getBinding());
    encodeResponse(decorator, response, context, samlResponse);
  }

  /**
   * A tweaked redirect decoder that ignores query parameters in the endpoint URL.
   */
  private final class RedirectDecoder extends HTTPRedirectDeflateDecoder {

    @Override
    protected boolean compareEndpointURIs(String messageDestination, String receiverEndpoint)
        throws MessageDecodingException {
      int q = messageDestination.indexOf('?');
      if (q > 0) {
        messageDestination = messageDestination.substring(0, q);
      }
      q = receiverEndpoint.indexOf('?');
      if (q > 0) {
        receiverEndpoint = receiverEndpoint.substring(0, q);
      }
      return super.compareEndpointURIs(messageDestination, receiverEndpoint);
    }
  }
}
