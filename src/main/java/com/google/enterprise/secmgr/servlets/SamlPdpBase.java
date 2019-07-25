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

package com.google.enterprise.secmgr.servlets;

import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getCheckMandatoryIssuerHandler;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getXmlSignatureHandler;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.initializeSecurityPolicy;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAction;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAssertion;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAuthzDecisionStatement;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeResponse;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeSubject;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeSuccessfulStatus;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runDecoder;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runEncoder;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runInboundMessageHandlers;

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.authzcontroller.Authorizer;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.modules.SamlAuthzClient.Protocol;
import com.google.enterprise.secmgr.saml.GsaAuthz;
import com.google.enterprise.secmgr.saml.HTTPSOAP11MultiContextDecoder;
import com.google.enterprise.secmgr.saml.HTTPSOAP11MultiContextEncoder;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.saml.SecmgrCredential;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
import org.opensaml.saml.saml2.core.Action;
import org.opensaml.saml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml.saml2.core.DecisionTypeEnumeration;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.soap.messaging.context.SOAP11Context;

/**
 * This class implements most of the logic needed for a SAML Policy Decision Point. To make a PDP,
 * the application provides an entity descriptor for the local entity, and an abstract "authorizer"
 * that maps resource/sessionId pairs to decisions.
 */
@Immutable
@ParametersAreNonnullByDefault
public final class SamlPdpBase {
  private static final Logger logger = Logger.getLogger(SamlPdpBase.class.getName());

  @Nonnull private final SamlSharedData sharedData;
  @Nonnull private final Authorizer authorizer;

  private SamlPdpBase(SamlSharedData sharedData, Authorizer authorizer) {
    this.sharedData = sharedData;
    this.authorizer = authorizer;
  }

  /**
   * Make a new PDP instance.
   *
   * @param sharedData A SAML shared-data object.
   * @param authorizer An abstract authorizer to make decisions about resource/sessionId pairs.
   * @return The new PDP instance.
   */
  @Nonnull
  public static SamlPdpBase make(SamlSharedData sharedData, Authorizer authorizer) {
    Preconditions.checkNotNull(sharedData);
    Preconditions.checkNotNull(authorizer);
    return new SamlPdpBase(sharedData, authorizer);
  }

  /**
   * Process a SAML AuthzDecisionQuery message.
   *
   * @param request The incoming servlet request with the query message.
   * @param response The outgoing servlet response which this method will
   *     initialize with the appropriate SAML Response message.
   * @throws IOException if there are errors while processing the request.
   */
  public void authorize(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    Decorator decorator = SessionUtil.getLogDecorator(request);
    Preconditions.checkNotNull(response);
    String sessionId = null;
    try {
      long startDecoding = System.currentTimeMillis();
      DecodedRequest decodedRequest = decodeAuthzRequest(request);
      sessionId = decodedRequest.getSessionId();
      long startAuthorizing = System.currentTimeMillis();
      DecodedResponse decodedResponse = authorize(decodedRequest, decorator);
      long startEncoding = System.currentTimeMillis();
      ServletBase.initResponse(response);
      encodeAuthzResponse(decodedResponse, response, decorator);
      long finishEncoding = System.currentTimeMillis();
      if (decodedRequest.getProtocol() != Protocol.STANDARD) {
        logger.info(
            decorator.apply(
                "Processed " + decodedRequest.getRecords().size() + " resources"
                + "; protocol: " + decodedRequest.getProtocol()
                + "; times (ms):"
                + " decoding " + (startAuthorizing - startDecoding)
                + " authorizing " + (startEncoding - startAuthorizing)
                + " encoding " + (finishEncoding - startEncoding)
                + " total " + (finishEncoding - startDecoding)));
      }
    } catch (IOException e) {
      logWithStackTrace(e, sessionId);
      throw e;
    } catch (RuntimeException e) {
      logWithStackTrace(e, sessionId);
      throw e;
    }
  }

  private static void logWithStackTrace(Throwable e, @Nullable String sessionId) {
    logger.log(Level.WARNING, SessionUtil.logMessage(sessionId, "Error while authorizing: "), e);
  }

  /**
   * Reads and decodes a SAML AuthzDecisionQuery message.
   *
   * @param servletRequest The incoming servlet request with the query message.
   * @return A decoded authorization query message.
   * @throws IOException if there are errors while processing the request.
   */
  @Nonnull
  public DecodedRequest decodeAuthzRequest(HttpServletRequest servletRequest)
      throws IOException {
    Decoder decoder = new Decoder(servletRequest);
    MessageContext<SAMLObject> context = decoder.decode();
    if (context == null) {
      return decodeBatch1AuthzRequest(decoder);
    }
    Extensions extensions = ((AuthzDecisionQuery) context.getMessage()).getExtensions();
    if (extensions != null && OpenSamlUtil.getChild(extensions, GsaAuthz.class) != null) {
      return decodeBatch2AuthzRequest(decoder, context);
    }
    MessageContext<SAMLObject> context2 = decoder.decode();
    if (context2 == null) {
      return decodeStandardAuthzRequest(decoder, context);
    }
    return decodeBatch1AuthzRequest(decoder, context, context2);
  }

  private final class Decoder {
    final Metadata metadata;
    final HTTPSOAP11Decoder soapDecoder;
    final Decorator decorator;
    boolean violationRecorded;

    Decoder(HttpServletRequest servletRequest)
        throws IOException {
      metadata = Metadata.getInstance(servletRequest);
      soapDecoder = new HTTPSOAP11MultiContextDecoder(OpenSamlUtil.getBasicParserPool());
      soapDecoder.setHttpServletRequest(servletRequest);
      decorator = SessionUtil.getLogDecorator(servletRequest);
      violationRecorded = false;
    }

    MessageContext<SAMLObject> decode() throws IOException {
      MessageContext<SAMLObject> context = sharedData.makeSamlMessageContext(metadata);
      initializeSecurityPolicy(context, getCheckMandatoryIssuerHandler(), getXmlSignatureHandler());
      try {
        runDecoder(soapDecoder, context, decorator);
        runInboundMessageHandlers(context);
      } catch (IndexOutOfBoundsException e) {
        // Normal indication that there are no more messages to decode.
        return null;
      } catch (MessageHandlerException e) {
        logger.warning(decorator.apply("Violation of security policy: " + e.getMessage()));
        violationRecorded = true;
      }
      return context;
    }

    boolean anyViolationsRecorded() {
      return violationRecorded;
    }
  }

  private DecodedRequest decodeStandardAuthzRequest(
      Decoder decoder, MessageContext<SAMLObject> context) {
    AuthzDecisionQuery authzDecisionQuery = (AuthzDecisionQuery) context.getMessage();
    String sessionId = authzDecisionQuery.getSubject().getNameID().getValue();

    SecmgrCredential cred = null;
    Extensions extensions = authzDecisionQuery.getExtensions();
    if (extensions != null) {
      cred = OpenSamlUtil.getChild(extensions, SecmgrCredential.class);
    }
    String resourceUrl = authzDecisionQuery.getResource();
    return new DecodedRequest(Protocol.STANDARD, sessionId, GsaAuthz.Mode.ALL,
        decoder.anyViolationsRecorded(), context,
        ImmutableList.of(new RequestRecord(resourceUrl, null, context)), cred);
  }

  private DecodedRequest decodeBatch1AuthzRequest(Decoder decoder) {
    return new DecodedRequest(Protocol.BATCH_V1, null, GsaAuthz.Mode.ALL,
        decoder.anyViolationsRecorded(), null, ImmutableList.<RequestRecord>of(), null);
  }

  private DecodedRequest decodeBatch1AuthzRequest(
      Decoder decoder, MessageContext<SAMLObject> context1, MessageContext<SAMLObject> context2)
      throws IOException {
    ImmutableList.Builder<RequestRecord> recordsBuilder = ImmutableList.builder();
    recordsBuilder.add(decodeOneBatch1Request(context1));
    recordsBuilder.add(decodeOneBatch1Request(context2));
    while (true) {
      MessageContext<SAMLObject> context = decoder.decode();
      if (context == null) {
        break;
      }
      recordsBuilder.add(decodeOneBatch1Request(context));
    }
    ImmutableList<RequestRecord> records = recordsBuilder.build();
    AuthzDecisionQuery authzDecisionQuery =
        (AuthzDecisionQuery) records.get(0).getContext().getMessage();
    String sessionId = authzDecisionQuery.getSubject().getNameID().getValue();
    SecmgrCredential cred = null;
    Extensions extensions = authzDecisionQuery.getExtensions();
    if (extensions != null) {
      cred = OpenSamlUtil.getChild(extensions, SecmgrCredential.class);
    }
    return new DecodedRequest(Protocol.BATCH_V1, sessionId, GsaAuthz.Mode.ALL,
        decoder.anyViolationsRecorded(), null, records, cred);
  }

  private RequestRecord decodeOneBatch1Request(MessageContext<SAMLObject> context) {
    AuthzDecisionQuery authzDecisionQuery = (AuthzDecisionQuery) context.getMessage();
    String resourceUrl = authzDecisionQuery.getResource();
    return new RequestRecord(resourceUrl, null, context);
  }

  private DecodedRequest decodeBatch2AuthzRequest(
      Decoder decoder, MessageContext<SAMLObject> context) {
    AuthzDecisionQuery authzDecisionQuery = (AuthzDecisionQuery) context.getMessage();
    String sessionId = authzDecisionQuery.getSubject().getNameID().getValue();

    Extensions extensions = authzDecisionQuery.getExtensions();
    GsaAuthz gsaAuthz = OpenSamlUtil.getChild(extensions, GsaAuthz.class);
    SecmgrCredential cred = OpenSamlUtil.getChild(extensions, SecmgrCredential.class);

    ImmutableList.Builder<RequestRecord> recordsBuilder = ImmutableList.builder();
    for (XMLObject object : extensions.getOrderedChildren()) {
      if (object instanceof com.google.enterprise.secmgr.saml.Resource) {
        com.google.enterprise.secmgr.saml.Resource resource
            = (com.google.enterprise.secmgr.saml.Resource) object;
        recordsBuilder.add(
            new RequestRecord(resource.getUri().toString(),
                resource.getDecision(), context));
      }
    }
    return new DecodedRequest(
        Protocol.BATCH_V2,
        sessionId,
        (gsaAuthz.getMode() != null) ? gsaAuthz.getMode() : GsaAuthz.Mode.ALL,
        decoder.anyViolationsRecorded(),
        context,
        recordsBuilder.build(),
        cred);
  }

  /**
   * Authorizes a decoded authorization request.
   *
   * @param request A decoded request to process.
   * @param decorator A log-message decorator.
   * @return A decoded response.
   */
  @Nonnull
  public DecodedResponse authorize(DecodedRequest request, Decorator decorator) {
    AuthzResult result = request.violatedSecurityPolicy()
        ? AuthzResult.makeIndeterminate(Resource.resourcesToUrls(request.getResources()))
        : authorizer.apply(request.getResources(), request.getSessionId(),
            request.getAuthzMode() == GsaAuthz.Mode.FAST);
    ImmutableList.Builder<ResponseRecord> builder = ImmutableList.builder();
    for (RequestRecord record : request.getRecords()) {
      String resourceUrl = record.getResource().getUrl();
      AuthzStatus status = result.get(resourceUrl);
      // Non-indeterminate status was already logged in AuthorizationMethodImpl.
      if (status == AuthzStatus.INDETERMINATE) {
        logger.info(decorator.apply(status.getDescription() + " for: " + resourceUrl));
      }
      builder.add(new ResponseRecord(record, status));
    }
    return new DecodedResponse(request, builder.build());
  }

  /**
   * Encodes and writes an authorization response.
   *
   * @param response The decoded response to encode.
   * @param servletResponse The servlet response to write to.
   * @param decorator A log-message decorator.
   * @throws IOException if there are errors while processing the request.
   */
  public void encodeAuthzResponse(DecodedResponse response, HttpServletResponse servletResponse,
      Decorator decorator)
      throws IOException {
    switch (response.getProtocol()) {
      case STANDARD:
        encodeStandardAuthzResponse(response, servletResponse, decorator);
        break;
      case BATCH_V1:
        encodeBatch1AuthzResponse(response, servletResponse, decorator);
        break;
      case BATCH_V2:
        encodeBatch2AuthzResponse(response, servletResponse, decorator);
        break;
      default:
        throw new IllegalStateException("Unknown protocol: " + response.getProtocol());
    }
  }

  private void encodeStandardAuthzResponse(DecodedResponse response,
      HttpServletResponse servletResponse, Decorator decorator)
      throws IOException {
    MessageContext<SAMLObject> context = response.getContext();
    context.setMessage(
        makeAuthzResponse(
            response.getSessionId(),
            response.getInResponseTo(),
            new DateTime(),
            response.getResponseRecords()));
    HTTPSOAP11Encoder encoder = new HTTPSOAP11Encoder();
    encoder.setHttpServletResponse(servletResponse);
    runEncoder(encoder, context, decorator);
  }

  private void encodeBatch1AuthzResponse(DecodedResponse response,
      HttpServletResponse servletResponse, Decorator decorator)
      throws IOException {
    String sessionId = response.getSessionId();
    DateTime now = new DateTime();
    HTTPSOAP11MultiContextEncoder encoder = new HTTPSOAP11MultiContextEncoder();
    MessageContext<SAMLObject> context = response.getResponseRecords().get(0).getContext();
    encoder.setHttpServletResponse(servletResponse);
    encoder.setMessageContext(context);
    for (ResponseRecord record : response.getResponseRecords()) {
      SAMLObject message =
          makeAuthzResponse(sessionId, record.getInResponseTo(), now, ImmutableList.of(record));
      context.setMessage(message);
      runEncoder(encoder, context, decorator);
    }
    try {
      encoder.finish();
    } catch (MessageEncodingException e) {
      throw new IOException(e);
    }
  }

  private void encodeBatch2AuthzResponse(DecodedResponse response,
      HttpServletResponse servletResponse, Decorator decorator)
      throws IOException {
    Response samlResponse
        = makeAuthzResponse(
            response.getSessionId(),
            response.getInResponseTo(),
            new DateTime(),
            response.getResponseRecords());

    MessageContext<SAMLObject> context = response.getContext();
    context.setMessage(samlResponse);
    HTTPSOAP11Encoder encoder = new HTTPSOAP11Encoder();
    encoder.setHttpServletResponse(servletResponse);
    runEncoder(encoder, context, decorator);
  }

  private Response makeAuthzResponse(String sessionId, String inResponseTo, DateTime now,
      Iterable<ResponseRecord> records) {
    // Note: We disregard the Action in the query and always return an
    // assertion about Action.HTTP_GET_ACTION. It's the only thing we know how
    // to test for. It might be argued that if the querier asked for anything
    // else, we should return INDETERMINATE. But I think it's more informative
    // to return information about what we do know than to return nothing.
    List<AuthzDecisionStatement> statements = Lists.newArrayList();
    for (ResponseRecord record : records) {
      statements.add(
          makeAuthzDecisionStatement(
              record.getResourceUrl(),
              convertStatus(record.getDecision()),
              makeAction(Action.HTTP_GET_ACTION, Action.GHPP_NS_URI)));
    }
    String issuer = sharedData.getLocalEntityId();
    return makeResponse(
        issuer,
        now,
        makeSuccessfulStatus(),
        inResponseTo,
        makeAssertion(issuer, now, makeSubject(sessionId), null, statements));
  }

  private DecisionTypeEnumeration convertStatus(AuthzStatus status) {
    switch (status) {
      case PERMIT: return DecisionTypeEnumeration.PERMIT;
      case DENY: return DecisionTypeEnumeration.DENY;
      default: return DecisionTypeEnumeration.INDETERMINATE;
    }
  }

  private static MessageContext<SAMLObject> removeSOAPContext(MessageContext<SAMLObject> context) {
    if (context == null) {
      return null;
    }
    context.removeSubcontext(SOAP11Context.class);
    return context;
  }

  /**
   * A decoded authorization request.
   */
  @Immutable
  public static final class DecodedRequest {
    @Nonnull private final Protocol protocol;
    @Nonnull private final String sessionId;
    @Nonnull private final GsaAuthz.Mode authzMode;
    private final boolean anySecurityViolations;
    @Nullable private final MessageContext<SAMLObject> context;
    @Nonnull private final ImmutableList<RequestRecord> records;
    @Nullable private final SecmgrCredential cred;

    private DecodedRequest(
        Protocol protocol,
        String sessionId,
        GsaAuthz.Mode authzMode,
        boolean anySecurityViolations,
        @Nullable MessageContext<SAMLObject> context,
        ImmutableList<RequestRecord> records,
        SecmgrCredential cred) {
      Preconditions.checkNotNull(protocol);
      Preconditions.checkNotNull(sessionId);
      Preconditions.checkNotNull(authzMode);
      Preconditions.checkNotNull(records);
      this.protocol = protocol;
      this.sessionId = sessionId;
      this.authzMode = authzMode;
      this.anySecurityViolations = anySecurityViolations;
      this.context = removeSOAPContext(context);
      this.records = records;
      this.cred = cred;
    }

    @Nonnull
    private Protocol getProtocol() {
      return protocol;
    }

    @Nonnull
    public String getSessionId() {
      return sessionId;
    }

    @Nullable
    public SecmgrCredential getCredential() {
      return cred;
    }

    @Nonnull
    private GsaAuthz.Mode getAuthzMode() {
      return authzMode;
    }

    @Nonnull
    private MessageContext<SAMLObject> getContext() {
      Preconditions.checkNotNull(context);
      return context;
    }

    @Nonnull
    private ImmutableList<RequestRecord> getRecords() {
      return records;
    }

    @Nonnull
    private ImmutableList<Resource> getResources() {
      return ImmutableList.copyOf(
          Iterables.transform(records,
              new Function<RequestRecord, Resource>() {
                @Override
                public Resource apply(RequestRecord record) {
                  return record.getResource();
                }
              }));
    }

    public boolean violatedSecurityPolicy() {
      return anySecurityViolations;
    }
  }

  @Immutable
  private static final class RequestRecord {
    @Nonnull private final Resource resource;
    @Nullable private final MessageContext<SAMLObject> context;

    RequestRecord(
        String url,
        @Nullable AuthzStatus earlyDecision,
        @Nullable MessageContext<SAMLObject> context) {
      Preconditions.checkNotNull(url);
      this.resource = new Resource(url, earlyDecision);
      this.context = removeSOAPContext(context);
    }

    @Nonnull
    Resource getResource() {
      return resource;
    }

    @Nonnull
    String getResourceUrl() {
      return resource.getUrl();
    }

    @Nonnull
    MessageContext<SAMLObject> getContext() {
      Preconditions.checkNotNull(context);
      return context;
    }
  }

  /**
   * A decoded authorization response.
   */
  @Immutable
  public static final class DecodedResponse {
    @Nonnull private final DecodedRequest request;
    @Nonnull private final ImmutableList<ResponseRecord> responseRecords;

    private DecodedResponse(DecodedRequest request, ImmutableList<ResponseRecord> responseRecords) {
      Preconditions.checkNotNull(request);
      Preconditions.checkNotNull(responseRecords);
      this.request = request;
      this.responseRecords = responseRecords;
    }

    @Nonnull
    private Protocol getProtocol() {
      return request.getProtocol();
    }

    @Nonnull
    private String getSessionId() {
      return request.getSessionId();
    }

    @Nonnull
    private MessageContext<SAMLObject> getContext() {
      return request.getContext();
    }

    @Nonnull
    private String getInResponseTo() {
      return ((AuthzDecisionQuery) getContext().getMessage()).getID();
    }

    @Nonnull
    private ImmutableList<ResponseRecord> getResponseRecords() {
      return responseRecords;
    }
  }

  @Immutable
  private static final class ResponseRecord {
    @Nonnull private final RequestRecord request;
    @Nonnull private final AuthzStatus decision;

    ResponseRecord(RequestRecord request, AuthzStatus decision) {
      Preconditions.checkNotNull(request);
      Preconditions.checkNotNull(decision);
      this.request = request;
      this.decision = decision;
    }

    @Nonnull
    String getResourceUrl() {
      return request.getResourceUrl();
    }

    @Nonnull
    private MessageContext<SAMLObject> getContext() {
      return request.getContext();
    }

    @Nonnull
    private String getInResponseTo() {
      return ((AuthzDecisionQuery) getContext().getMessage()).getID();
    }

    @Nonnull
    AuthzStatus getDecision() {
      return decision;
    }
  }
}
