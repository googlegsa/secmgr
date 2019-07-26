/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.enterprise.secmgr.mock;

import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runEncoder;

import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.http.HttpClientUtil;
import com.google.enterprise.secmgr.http.HttpExchange;
import com.google.enterprise.secmgr.saml.HttpExchangeToHttpServletRequest;
import com.google.enterprise.secmgr.saml.HttpExchangeToHttpServletResponse;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import java.io.IOException;
import java.net.URL;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.joda.time.DateTime;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLSelfEntityContext;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.Credential;

/**
 * An implementation of a servlet pretending to be a non-GSA service provider
 * that interacts with the security manager.
 */
public class MockAlternateServiceProvider extends ServletBase
    implements MockServer, GettableHttpServlet, PostableHttpServlet {

  private final String localEntityId;
  private final String gsaHost;
  private final String contextUrl;
  private final String acsUrl;
  private final String protocolBinding;
  private final Credential signingCredential;
  private final Decorator decorator;

  public MockAlternateServiceProvider(String localEntityId, String gsaHost, String contextUrl,
      String protocolBinding, Credential signingCredential) {
    this.localEntityId = localEntityId;
    this.gsaHost = gsaHost;
    this.contextUrl = contextUrl;
    acsUrl = contextUrl + "/assertion-consumer-service";
    this.protocolBinding = protocolBinding;
    this.signingCredential = signingCredential;
    decorator = SessionUtil.getLogDecorator();
  }

  @Override
  public void addToIntegration(MockIntegration integration)
      throws ServletException {
    MockHttpTransport transport = integration.getHttpTransport();
    transport.registerContextUrl(contextUrl);
    transport.registerServlet(acsUrl, this);
  }

  @Override
  public String getContextUrl() {
    return contextUrl;
  }

  @Override
  public String getSampleUrl() {
    return acsUrl;
  }

  @Override
  public void reset() {
  }

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    if (request.getParameter("SAMLart") == null) {
      // This is the initial request.
      Endpoint endpoint = MockIntegration.getSamlAuthnEndpoint(gsaHost);
      MessageContext<SAMLObject> context = makeAuthnContext(endpoint);
      sendAuthnRequest(makeAuthnRequest(endpoint), response, context);
      return;
    }
    // This is the response to that request.
    consumeResponse(decodeArtifactResponse(request), response);
  }

  private MessageContext<SAMLObject> makeAuthnContext(Endpoint endpoint) throws IOException {
    MessageContext<SAMLObject> context = makeContext();
    context
        .getSubcontext(SAMLPeerEntityContext.class)
        .getSubcontext(SAMLEndpointContext.class, true)
        .setEndpoint(endpoint);
    return context;
  }

  private AuthnRequest makeAuthnRequest(Endpoint endpoint) {
    AuthnRequest authnRequest = OpenSamlUtil.makeAuthnRequest(localEntityId, new DateTime());
    authnRequest.setIsPassive(false);
    authnRequest.setAssertionConsumerServiceURL(acsUrl);
    authnRequest.setProtocolBinding(protocolBinding);
    authnRequest.setDestination(endpoint.getLocation());
    return authnRequest;
  }

  private void sendAuthnRequest(
      AuthnRequest request, HttpServletResponse response, MessageContext<SAMLObject> context)
      throws IOException {
    context.setMessage(request);
    HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
    encoder.setHttpServletResponse(response);
    runEncoder(encoder, context, decorator);
  }

  private Response decodeArtifactResponse(HttpServletRequest request)
      throws IOException {
    return resolveArtifact(request, getArtifact(request));
  }

  private String getArtifact(HttpServletRequest request)
      throws IOException {
    String artifact = request.getParameter("SAMLart");
    if (artifact == null) {
      throw new IOException("No artifact in message");
    }
    return artifact;
  }

  private Response resolveArtifact(HttpServletRequest request, String artifact)
      throws IOException {
    // Establish the SAML message context.
    MessageContext<SAMLObject> context = makeArtifactContext();

    // Generate the request.
    context.setMessage(OpenSamlUtil.makeArtifactResolve(localEntityId, DateTime.now(), artifact));

    // Encode the request.
    HttpExchange exchange =
        HttpClientUtil.postExchange(
            new URL(
                context
                    .getSubcontext(SAMLPeerEntityContext.class)
                    .getSubcontext(SAMLEndpointContext.class)
                    .getEndpoint()
                    .getLocation()),
            null);
    try {
      HttpExchangeToHttpServletResponse out = new HttpExchangeToHttpServletResponse(exchange);
      try {
        HTTPSOAP11Encoder encoder = new HTTPSOAP11Encoder();
        encoder.setHttpServletResponse(out);
        SAMLBindingSupport.setRelayState(context, request.getParameter("RelayState"));

        OpenSamlUtil.runEncoder(encoder, context, decorator);
      } finally {
        out.finish();
      }
    } finally {
      exchange.close();
    }

    // Do HTTP exchange.
    int status = exchange.exchange();
    if (status != HttpServletResponse.SC_OK) {
      throw new IOException("Incorrect HTTP status: " + status);
    }

    // Decode the response.
    HTTPSOAP11Decoder decoder = new HTTPSOAP11Decoder();
    decoder.setHttpServletRequest(new HttpExchangeToHttpServletRequest(exchange));
    OpenSamlUtil.runDecoder(decoder, context, decorator);

    // Return the decoded response.
    ArtifactResponse artifactResponse = (ArtifactResponse) context.getMessage();
    if (artifactResponse == null) {
      throw new IOException("Decoded SAML response is null");
    }
    return (Response) artifactResponse.getMessage();
  }

  private MessageContext<SAMLObject> makeArtifactContext() throws IOException {
    MessageContext<SAMLObject> context = makeContext();
    SAMLPeerEntityContext peerEntityContext =
        context.getSubcontext(SAMLPeerEntityContext.class, true);
    SAMLEndpointContext endpointContext =
        peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
    endpointContext.setEndpoint(MockIntegration.getSamlArtifactResolverEndpoint(gsaHost));
    return context;
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    consumeResponse(decodePostResponse(request), response);
  }

  private Response decodePostResponse(HttpServletRequest request)
      throws IOException {
    MessageContext<SAMLObject> context = makeContext();
    HTTPPostDecoder decoder = new HTTPPostDecoder();
    decoder.setHttpServletRequest(request);
    OpenSamlUtil.runDecoder(decoder, context, decorator);
    return (Response) context.getMessage();
  }

  private void consumeResponse(Response samlResponse, HttpServletResponse response)
      throws IOException {
    if (samlResponse == null) {
      MockServiceProvider.errorResponse(response);
      return;
    }
    String code = samlResponse.getStatus().getStatusCode().getValue();
    if (code.equals(StatusCode.SUCCESS)) {
      MockServiceProvider.positiveResponse(response);
    } else if (code.equals(StatusCode.AUTHN_FAILED)) {
      MockServiceProvider.negativeResponse(response);
    } else {
      MockServiceProvider.errorResponse(response);
    }
  }

  private <T extends SAMLObject> MessageContext<T> makeContext() throws IOException {
    MessageContext<T> context = OpenSamlUtil.makeSamlMessageContext();
    SAMLPeerEntityContext peerEntityContext =
        context.getSubcontext(SAMLPeerEntityContext.class, true);
    SAMLSelfEntityContext selfEntityContext =
        context.getSubcontext(SAMLSelfEntityContext.class, true);
    selfEntityContext.setEntityId(localEntityId);
    selfEntityContext.setRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
    peerEntityContext.setEntityId(Metadata.getSmEntityId());

    SAMLMetadataContext peerMetadataContext =
        peerEntityContext.getSubcontext(SAMLMetadataContext.class, true);
    peerMetadataContext.setEntityDescriptor(MockIntegration.getSmEntity(gsaHost));
    peerMetadataContext.setRoleDescriptor(MockIntegration.getSmIdpSsoDescriptor(gsaHost));
    peerEntityContext.setRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
    OpenSamlUtil.initializeSigningParameters(context, signingCredential);
    return context;
  }
}
