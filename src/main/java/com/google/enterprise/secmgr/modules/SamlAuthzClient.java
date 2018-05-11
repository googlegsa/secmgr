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

import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getMandatoryIssuerRule;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getXmlSignatureRule;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.initializeSecurityPolicy;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAction;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAuthzDecisionQuery;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeSubject;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runDecoder;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runEncoder;
import static org.opensaml.common.xml.SAMLConstants.SAML2_SOAP11_BINDING_URI;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.http.HttpClientUtil;
import com.google.enterprise.secmgr.http.HttpExchange;
import com.google.enterprise.secmgr.saml.GsaAuthz;
import com.google.enterprise.secmgr.saml.HTTPSOAP11MultiContextDecoder;
import com.google.enterprise.secmgr.saml.HTTPSOAP11MultiContextEncoder;
import com.google.enterprise.secmgr.saml.HttpExchangeToInTransport;
import com.google.enterprise.secmgr.saml.HttpExchangeToOutTransport;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.saml.SecmgrCredential;

import org.joda.time.DateTime;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.decoding.HTTPSOAP11Decoder;
import org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder;
import org.opensaml.saml2.core.Action;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml2.core.DecisionTypeEnumeration;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Statement;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.metadata.AuthzService;
import org.opensaml.ws.message.encoder.MessageEncoder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.SecurityException;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.Collection;
import java.util.List;
import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.ThreadSafe;

/**
 * A library implementing most of the functionality of a SAML Relying Party
 * using the Assertion Query/Request Profile to process AuthzDecisionQuery
 * requests.
 */
@ThreadSafe
@ParametersAreNonnullByDefault
public final class SamlAuthzClient {
  private static final Logger logger = Logger.getLogger(SamlAuthzClient.class.getName());

  /**
   * The SAML AuthzDecisionQuery protocol to use:
   * STANDARD is SAML standard protocol
   * BATCH_V1 is GSA's original protocol extension
   * BATCH_V2 is GSA's current protocol extension
   */
  public enum Protocol { STANDARD, BATCH_V1, BATCH_V2 }

  @Nonnull private final Metadata metadata;
  @Nonnull private final String peerEntityId;
  @Nonnull private final SamlSharedData sharedData;

  private SamlAuthzClient(Metadata metadata, String peerEntityId, SamlSharedData sharedData) {
    this.metadata = metadata;
    this.peerEntityId = peerEntityId;
    this.sharedData = sharedData;
  }

  /**
   * Creates an instance of the authorization client library.
   *
   * @param metadata Metadata to use when encoding and decoding messages.
   * @param peerEntityId The entity ID of the peer.
   * @param sharedData A shared-data object to supply signing credential, etc.
   */
  @Nonnull
  public static SamlAuthzClient make(Metadata metadata, String peerEntityId,
      SamlSharedData sharedData) {
    Preconditions.checkNotNull(metadata);
    Preconditions.checkNotNull(peerEntityId);
    Preconditions.checkNotNull(sharedData);
    Preconditions.checkArgument(sharedData.getRole() == SamlSharedData.Role.AUTHZ_CLIENT);
    return new SamlAuthzClient(metadata, peerEntityId, sharedData);
  }

  /**
   * Gets the metadata for this client.
   */
  @Nonnull
  public Metadata getMetadata() {
    return metadata;
  }

  /**
   * Gets the local entity ID for this client.
   */
  @Nonnull
  public String getLocalEntityId() {
    return sharedData.getLocalEntityId();
  }

  /**
   * Gets the peer entity ID for this client.
   */
  @Nonnull
  public String getPeerEntityId() {
    return peerEntityId;
  }

  /**
   * Send multiple SAML authorization requests.
   *
   * @param protocol The protocol to use for the requests.
   * @param urls The URLs for which access is being authorized.
   * @param cred, The credential which will be passed to authz authority.
   * @param decorator A log-message decorator.
   * @return The authorization responses.
   * @throws IOException if there are I/O errors during the message exchange.
   * @throws SecurityException if the response violates the security policy.
   */
  public AuthzResult sendAuthzRequest(Protocol protocol, Collection<String> urls,
      SecmgrCredential cred, Decorator decorator, int timeout)
      throws IOException, SecurityException {
    return sendAuthzRequest(protocol, urls, cred, false, decorator, timeout);
  }

  /**
   * Send multiple SAML authorization requests.
   *
   * @param protocol The protocol to use for the requests.
   * @param urls The URLs for which access is being authorized.
   * @param cred, The credential which will be passed to authz authority.
   * @param useFastAuthz Whether to use "fast" authz mode (BATCH_V2 protocol only).
   * @param decorator A log-message decorator.
   * @return The authorization responses.
   * @throws IOException if there are I/O errors during the message exchange.
   * @throws SecurityException if the response violates the security policy.
   */
  public AuthzResult sendAuthzRequest(Protocol protocol, Collection<String> urls,
      SecmgrCredential cred, boolean useFastAuthz, Decorator decorator, int timeout)
      throws IOException, SecurityException {
    Preconditions.checkNotNull(cred);
    if (urls.isEmpty()) {
      return AuthzResult.makeIndeterminate(urls);
    }

    AuthzResult.Builder builder = AuthzResult.builder(urls);
    logger.fine(decorator.apply("protocol: " + protocol));
    switch (protocol) {
      case STANDARD:
        for (String url : urls) {
          sendStandardAuthzRequest(url, cred, builder, decorator, timeout);
        }
        break;
      case BATCH_V1:
        sendBatch1AuthzRequest(urls, cred, builder, decorator, timeout);
        break;
      case BATCH_V2:
        sendBatch2AuthzRequest(urls, cred, useFastAuthz, builder, decorator, timeout);
        break;
      default:
        throw new IllegalStateException("Unknown protocol: " + protocol);
    }
    return builder.build();
  }

  private void sendStandardAuthzRequest(String url, SecmgrCredential cred,
      AuthzResult.Builder builder, Decorator decorator, int timeout)
      throws IOException, SecurityException {
    SAMLMessageContext<Response, AuthzDecisionQuery, NameID> context = makeAuthzContext();
    HttpExchange exchange = makeAuthzExchange(context);
    exchange.setTimeout(timeout);
    try {

      HttpExchangeToOutTransport out = new HttpExchangeToOutTransport(exchange);
      setupAuthzQuery(context, url, cred, /*withCredential*/true, new DateTime(), out,
          new HTTPSOAP11Encoder(), decorator);
      out.finish();

      // Do HTTP exchange
      int status = exchange.exchange();
      if (!HttpUtil.isGoodHttpStatus(status)) {
        throw new IOException("Incorrect HTTP status: " + status);
      }

      // Decode the response
      HttpExchangeToInTransport in = new HttpExchangeToInTransport(exchange);
      context.setInboundMessageTransport(in);
      runDecoder(new HTTPSOAP11Decoder(OpenSamlUtil.getBasicParserPool()), context, decorator,
          Response.DEFAULT_ELEMENT_NAME);

    } finally {
      exchange.close();
    }

    String subject = cred.getName();
    decodeAuthzResponse(context.getInboundSAMLMessage(), subject, builder, decorator);
  }

  private void sendBatch1AuthzRequest(Collection<String> urls, SecmgrCredential cred,
      AuthzResult.Builder builder, Decorator decorator, int timeout)
      throws IOException, SecurityException {
    SAMLMessageContext<Response, AuthzDecisionQuery, NameID> context = makeAuthzContext();
    HTTPSOAP11MultiContextEncoder encoder = new HTTPSOAP11MultiContextEncoder();
    HttpExchange exchange = makeAuthzExchange(context);
    exchange.setTimeout(timeout);
    try {

      HttpExchangeToOutTransport out = new HttpExchangeToOutTransport(exchange);
      DateTime now = new DateTime();

      boolean firstQuery = true;
      for (String url : urls) {
        setupAuthzQuery(context, url, cred, /*withCredential*/firstQuery, now, out, encoder,
            decorator);
        firstQuery = false;
      }
      try {
        encoder.finish();
      } catch (MessageEncodingException e) {
        throw new IOException(e);
      }
      out.finish();

      // Do HTTP exchange
      int status = exchange.exchange();
      if (!HttpUtil.isGoodHttpStatus(status)) {
        throw new IOException("Incorrect HTTP status: " + status);
      }

      // Decode the responses
      HttpExchangeToInTransport in = new HttpExchangeToInTransport(exchange);
      context.setInboundMessageTransport(in);
      HTTPSOAP11MultiContextDecoder decoder = new HTTPSOAP11MultiContextDecoder(
          OpenSamlUtil.getBasicParserPool());

      String subject = cred.getName();
      while (true) {
        try {
          runDecoder(decoder, context, decorator, Response.DEFAULT_ELEMENT_NAME);
        } catch (IndexOutOfBoundsException e) {
          // normal indication that there are no more messages to decode
          break;
        }
        decodeAuthzResponse(context.getInboundSAMLMessage(), subject, builder, decorator);
      }

    } finally {
      exchange.close();
    }
  }

  private void sendBatch2AuthzRequest(Collection<String> urls, SecmgrCredential cred,
      boolean useFastAuthz, AuthzResult.Builder builder, Decorator decorator, int timeout)
      throws IOException, SecurityException {
    AuthzDecisionQuery query = makeBatch2AuthzQuery(cred, useFastAuthz, urls);

    SAMLMessageContext<Response, AuthzDecisionQuery, NameID> context = makeAuthzContext();
    HttpExchange exchange = makeAuthzExchange(context);
    exchange.setTimeout(timeout);
    try {
      // Encode the request.
      HttpExchangeToOutTransport out = new HttpExchangeToOutTransport(exchange);
      context.setOutboundSAMLMessage(query);
      context.setOutboundMessageTransport(out);
      runEncoder(new HTTPSOAP11Encoder(), context, decorator);
      out.finish();

      // Do HTTP exchange.
      int status = exchange.exchange();
      if (!HttpUtil.isGoodHttpStatus(status)) {
        throw new IOException("Incorrect HTTP status: " + status);
      }

      // Decode the response.
      context.setInboundMessageTransport(new HttpExchangeToInTransport(exchange));
      runDecoder(new HTTPSOAP11Decoder(OpenSamlUtil.getBasicParserPool()), context, decorator,
          Response.DEFAULT_ELEMENT_NAME);
    } finally {
      exchange.close();
    }
    String subject = cred.getName();
    decodeAuthzResponse(context.getInboundSAMLMessage(), subject, builder, decorator);
  }

  private AuthzDecisionQuery makeBatch2AuthzQuery(SecmgrCredential cred, boolean useFastAuthz,
      Iterable<String> urls) {
    AuthzDecisionQuery query = makeAuthzQuery(new DateTime(), cred, /*withCredential*/false, "");
    List<XMLObject> extensions = Lists.newArrayList();
    extensions.add(OpenSamlUtil.makeGsaAuthz(GsaAuthz.CURRENT_VERSION,
            useFastAuthz ? GsaAuthz.Mode.FAST : null));
    for (String url : urls) {
      extensions.add(OpenSamlUtil.makeResource(URI.create(url), null, null));
    }
    extensions.add(OpenSamlUtil.makeSecmgrCredential(
        cred.getName(),
        cred.getNamespace(),
        cred.getDomain(),
        cred.getPassword(),
        cred.getGroups()));
    query.setExtensions(OpenSamlUtil.makeExtensions(extensions));
    return query;
  }

  private SAMLMessageContext<Response, AuthzDecisionQuery, NameID> makeAuthzContext()
      throws IOException {
    // Establish the SAML message context.
    SAMLMessageContext<Response, AuthzDecisionQuery, NameID> context
        = sharedData.makeSamlMessageContext(metadata);
    initializeSecurityPolicy(context,
        getMandatoryIssuerRule(),
        getXmlSignatureRule());
    sharedData.initializePeerEntity(context, peerEntityId,
        AuthzService.DEFAULT_ELEMENT_NAME,
        SAML2_SOAP11_BINDING_URI);
    return context;
  }

  private HttpExchange makeAuthzExchange(
      SAMLMessageContext<Response, AuthzDecisionQuery, NameID> context)
      throws IOException {
    return HttpClientUtil.postExchange(
        new URL(context.getPeerEntityEndpoint().getLocation()),
        null);
  }

  private void setupAuthzQuery(SAMLMessageContext<Response, AuthzDecisionQuery, NameID> context,
      String url, SecmgrCredential cred, boolean withCredential, DateTime instant,
      HTTPOutTransport out, MessageEncoder encoder, Decorator decorator)
      throws IOException {
    AuthzDecisionQuery query = makeAuthzQuery(instant, cred, withCredential, url);
    context.setOutboundSAMLMessage(query);
    context.setOutboundMessageTransport(out);
    runEncoder(encoder, context, decorator);
  }

  private AuthzDecisionQuery makeAuthzQuery(DateTime instant, SecmgrCredential cred,
      boolean withCredential, String resource) {
    String subject = cred.getName();
    AuthzDecisionQuery query = makeAuthzDecisionQuery(getLocalEntityId(), instant,
        makeSubject(subject), resource, makeAction(Action.HTTP_GET_ACTION, Action.GHPP_NS_URI));
    if (withCredential) {
      List<XMLObject> extensions = Lists.newArrayList();
      extensions.add(cred);
      query.setExtensions(OpenSamlUtil.makeExtensions(extensions));
    }
    return query;
  }

  private void decodeAuthzResponse(Response response, String subject, AuthzResult.Builder builder,
      Decorator decorator) {

    String statusValue = response.getStatus().getStatusCode().getValue();
    if (!StatusCode.SUCCESS_URI.equals(statusValue)) {
      logger.info(decorator.apply("Unsuccessful response received: " + statusValue));
      return;
    }

    for (Assertion assertion : response.getAssertions()) {
      if (subject.equals(assertion.getSubject().getNameID().getValue())) {
        for (Statement rawStatement : assertion.getStatements()) {
          if (rawStatement instanceof AuthzDecisionStatement) {
            AuthzDecisionStatement statement = (AuthzDecisionStatement) rawStatement;
            builder.put(
                statement.getResource(),
                mapDecision(statement.getDecision()));
          }
        }
      }
    }
  }

  private AuthzStatus mapDecision(DecisionTypeEnumeration decision) {
    if (decision == DecisionTypeEnumeration.PERMIT) {
      return AuthzStatus.PERMIT;
    } else if (decision == DecisionTypeEnumeration.DENY) {
      return AuthzStatus.DENY;
    } else {
      return AuthzStatus.INDETERMINATE;
    }
  }
}
