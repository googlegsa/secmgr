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

import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.http.HttpClientUtil;
import com.google.enterprise.secmgr.http.HttpExchange;
import com.google.enterprise.secmgr.saml.HttpExchangeToInTransport;
import com.google.enterprise.secmgr.saml.HttpExchangeToOutTransport;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import java.io.IOException;
import java.net.URL;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPSOAP11Decoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;

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
      SAMLMessageContext<Response, SAMLObject, NameID> context = makeAuthnContext(endpoint);
      sendAuthnRequest(makeAuthnRequest(endpoint), response, context);
      return;
    }
    // This is the response to that request.
    consumeResponse(decodeArtifactResponse(request), response);
  }

  private SAMLMessageContext<Response, SAMLObject, NameID> makeAuthnContext(Endpoint endpoint)
      throws IOException {
    SAMLMessageContext<Response, SAMLObject, NameID> context = makeContext();
    context.setPeerEntityEndpoint(endpoint);
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

  private void sendAuthnRequest(AuthnRequest request, HttpServletResponse response,
      SAMLMessageContext<Response, SAMLObject, NameID> context)
      throws IOException {
    context.setOutboundSAMLMessage(request);
    context.setOutboundMessageTransport(new HttpServletResponseAdapter(response, true));
    OpenSamlUtil.runEncoder(new HTTPRedirectDeflateEncoder(), context, decorator);
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
    SAMLMessageContext<ArtifactResponse, ArtifactResolve, NameID> context = makeArtifactContext();

    // Generate the request.
    context.setOutboundSAMLMessage(
        OpenSamlUtil.makeArtifactResolve(localEntityId, new DateTime(), artifact));

    // Encode the request.
    HttpExchange exchange
        = HttpClientUtil.postExchange(new URL(context.getPeerEntityEndpoint().getLocation()), null);
    try {
      HttpExchangeToOutTransport out = new HttpExchangeToOutTransport(exchange);
      try {
        context.setOutboundMessageTransport(out);
        context.setRelayState(request.getParameter("RelayState"));
        OpenSamlUtil.runEncoder(new HTTPSOAP11Encoder(), context, decorator);
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
    context.setInboundMessageTransport(new HttpExchangeToInTransport(exchange));
    try {
      OpenSamlUtil.runDecoder(new HTTPSOAP11Decoder(), context, decorator,
          ArtifactResponse.DEFAULT_ELEMENT_NAME);
    } catch (SecurityException e) {
      throw new IOException(e);
    }

    // Return the decoded response.
    ArtifactResponse artifactResponse = context.getInboundSAMLMessage();
    if (artifactResponse == null) {
      throw new IOException("Decoded SAML response is null");
    }
    return (Response) artifactResponse.getMessage();
  }

  private SAMLMessageContext<ArtifactResponse, ArtifactResolve, NameID> makeArtifactContext()
      throws IOException {
    SAMLMessageContext<ArtifactResponse, ArtifactResolve, NameID> context = makeContext();
    context.setPeerEntityEndpoint(MockIntegration.getSamlArtifactResolverEndpoint(gsaHost));
    return context;
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    consumeResponse(decodePostResponse(request), response);
  }

  private Response decodePostResponse(HttpServletRequest request)
      throws IOException {
    SAMLMessageContext<Response, SAMLObject, NameID> context = makeContext();
    context.setInboundMessageTransport(new HttpServletRequestAdapter(request));
    try {
      OpenSamlUtil.runDecoder(new HTTPPostDecoder(), context, decorator,
          Response.DEFAULT_ELEMENT_NAME);
    } catch (SecurityException e) {
      throw new IOException(e);
    }
    return context.getInboundSAMLMessage();
  }

  private void consumeResponse(Response samlResponse, HttpServletResponse response)
      throws IOException {
    if (samlResponse == null) {
      MockServiceProvider.errorResponse(response);
      return;
    }
    String code = samlResponse.getStatus().getStatusCode().getValue();
    if (code.equals(StatusCode.SUCCESS_URI)) {
      MockServiceProvider.positiveResponse(response);
    } else if (code.equals(StatusCode.AUTHN_FAILED_URI)) {
      MockServiceProvider.negativeResponse(response);
    } else {
      MockServiceProvider.errorResponse(response);
    }
  }

  private <TI extends SAMLObject, TO extends SAMLObject, TN extends SAMLObject>
      SAMLMessageContext<TI, TO, TN> makeContext()
      throws IOException {
    SAMLMessageContext<TI, TO, TN> context = OpenSamlUtil.makeSamlMessageContext();
    context.setOutboundMessageIssuer(localEntityId);
    context.setLocalEntityId(localEntityId);
    context.setLocalEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
    context.setPeerEntityId(Metadata.getSmEntityId());
    context.setPeerEntityMetadata(MockIntegration.getSmEntity(gsaHost));
    context.setPeerEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
    context.setPeerEntityRoleMetadata(MockIntegration.getSmIdpSsoDescriptor(gsaHost));
    context.setOutboundSAMLMessageSigningCredential(signingCredential);
    return context;
  }
}
