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

package com.google.enterprise.secmgr.servlets;

import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getAuthnRequestsSignedHandler;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getBasicParserPool;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getRedirectSignatureHandler;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.initializeSecurityPolicy;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAssertionConsumerService;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runDecoder;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runInboundMessageHandlers;

import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSession.AuthnState;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.inject.Singleton;
import java.io.IOException;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

/**
 * Handler for SAML authentication requests. These requests are sent by a service provider, in our
 * case the Google Search Appliance. This is one part of the security manager's identity provider.
 */
@Singleton
@Immutable
public class SamlAuthn extends SamlIdpServlet
    implements GettableHttpServlet, PostableHttpServlet {
  private static final Logger logger = Logger.getLogger(SamlAuthn.class.getName());

  // TODO: I18N this message.
  protected static final String PLEASE_ENABLE_COOKIES_MSG = "Please enable cookies";
  @Nonnull private final AuthnController controller;

  @Inject
  private SamlAuthn() {
    super(SamlSharedData.getProductionInstance(SamlSharedData.Role.IDENTITY_PROVIDER));
    controller = ConfigSingleton.getInstance(AuthnController.class);
  }

  /**
   * Accept an authentication request and (eventually) respond to the service provider with a
   * response.  The request is generated by the service provider, then sent to the user agent as a
   * redirect.  The user agent redirects here, with the SAML AuthnRequest message encoded as a query
   * parameter.
   */
  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    Decorator decorator = SessionUtil.getLogDecorator(request);
    controller.setSecureSearchApiMode(false);
    AuthnSession.setSecureSearchApiMode(false);
    AuthnSession session = AuthnSession.getInstance(request,
        /*createGsaSmSessionIfNotExist=*/true);
    if (session == null) {
      logger.warning(decorator.apply("Could not get/make session; abandoning request."));
      initNormalResponseWithHeaders(response, HttpServletResponse.SC_EXPECTATION_FAILED)
        .print(PLEASE_ENABLE_COOKIES_MSG);
      return;
    }
    session.logIncomingRequest(request);

    try {

      // If the session is newly created in AuthnSession#getInstance due to
      // createGsaSmSessionIfNotExist is set to true, then it must be in
      // AuthnState.IDLE.
      if (session.assertState(AuthnState.IDLE, AuthnState.IN_CREDENTIALS_GATHERER)
          == AuthnState.IN_CREDENTIALS_GATHERER) {
        doAuthn(session, request, response);
        return;
      }

      // Establish the SAML message context.
      MessageContext<SAMLObject> context = makeSamlMessageContext(request);
      initializeSecurityPolicy(
          context, getAuthnRequestsSignedHandler(), getRedirectSignatureHandler(request));

      // Decode the request.
      HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
      decoder.setHttpServletRequest(request);
      decoder.setParserPool(getBasicParserPool());
      MessageHandlerException messsageHandlerException = null;
      try {
        runDecoder(decoder, context, decorator);
        initializePeerEntity(
            context,
            AssertionConsumerService.DEFAULT_ELEMENT_NAME,
            SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
        runInboundMessageHandlers(context);
      } catch (IOException e) {
        if (e.getCause() instanceof MessageDecodingException) {
          initErrorResponse(response, HttpServletResponse.SC_FORBIDDEN);
          return;
        }
        throw e;
      } catch (MessageHandlerException e) {
        messsageHandlerException = e;
      }

      // Now, some complicated logic to determine where to send the response.
      Endpoint embeddedEndpoint = getEmbeddedEndpoint((AuthnRequest) context.getMessage());
      if (embeddedEndpoint == null) {
        // Normal case: we use metadata to identify the peer.
        // If there's no metadata available, we can't process the request.
        // Generate an error and send it back to the user agent.
        if (getPeerEntityMetadata(context) == null && messsageHandlerException == null) {
          messsageHandlerException =
              new MessageHandlerException(
                  "Service provider didn't provide an assertion consumer endpoint.");
        }
      } else {
        // We have an embedded endpoint.
        if (context.getSubcontext(SAMLPeerEntityContext.class).isAuthenticated()) {
          // If the message is signed, then send the response to the embedded
          // endpoint.
          SAMLEndpointContext endpointContext = getPeerEntityEndpointContext(context);
          endpointContext.setEndpoint(embeddedEndpoint);

        } else {
          // Otherwise, use metadata to determine the endpoint. If there's no metadata, send an 
          // error response to the embedded endpoint.
          if (getPeerEntityMetadata(context) == null) {
            SAMLEndpointContext endpointContext = getPeerEntityEndpointContext(context);
            endpointContext.setEndpoint(embeddedEndpoint);
            if (messsageHandlerException == null) {
              messsageHandlerException =
                  new MessageHandlerException("Unable to authenticate request issuer");
            }
          }
        }
      }

      // If we are here, we've received a valid SAML SSO request.  If the GET
      // request was not a SAML SSO request, an error would have been signalled
      // during decoding and we wouldn't reach this point.
      session.setStateAuthenticating(HttpUtil.getRequestUrl(request, false), context);

      // If the incoming request violated security policy, return now with
      // failure.  This must happen AFTER going into "authenticating" state, so
      // that the SAML response is properly generated.
      if (messsageHandlerException != null) {
        failFromException(messsageHandlerException, session, request, response);
        return;
      }

      // Start authentication process.
      doAuthn(session, request, response);

    } catch (IOException | RuntimeException e) {
      failFromException(e, session, request, response);
    }
  }

  private SAMLEndpointContext getPeerEntityEndpointContext(MessageContext<SAMLObject> context) {
    SAMLPeerEntityContext peerEntityContext =
        context.getSubcontext(SAMLPeerEntityContext.class, true);
    SAMLEndpointContext endpointContext =
        peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
    return endpointContext;
  }

  private EntityDescriptor getPeerEntityMetadata(MessageContext<SAMLObject> context) {
    return context
        .getSubcontext(SAMLPeerEntityContext.class, true)
        .getSubcontext(SAMLMetadataContext.class, true)
        .getEntityDescriptor();
  }

  private Endpoint getEmbeddedEndpoint(AuthnRequest authnRequest) {
    String url = authnRequest.getAssertionConsumerServiceURL();
    String binding = authnRequest.getProtocolBinding();
    return (url != null && binding != null)
        ? makeAssertionConsumerService(url, binding)
        : null;
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    controller.setSecureSearchApiMode(false);
    AuthnSession.setSecureSearchApiMode(false);
    AuthnSession session = AuthnSession.getInstance(request,
        /*createGsaSmSessionIfNotExist=*/false);
    if (session == null) {
      failNoSession(request, response);
      return;
    }
    session.logIncomingRequest(request);
    try {
      session.assertState(AuthnState.IN_UL_FORM, AuthnState.IN_CREDENTIALS_GATHERER);
      doAuthn(session, request, response);
    } catch (IOException e) {
      failFromException(e, session, request, response);
    } catch (RuntimeException e) {
      failFromException(e, session, request, response);
    }
  }
}