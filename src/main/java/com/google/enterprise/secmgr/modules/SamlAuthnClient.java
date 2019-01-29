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

import static com.google.enterprise.secmgr.saml.MetadataEditor.SAML_BINDING_HTTP_ARTIFACT;
import static com.google.enterprise.secmgr.saml.MetadataEditor.SAML_BINDING_HTTP_POST;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getBasicParserPool;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getMandatoryAuthenticatedMessageRule;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getMandatoryIssuerRule;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.getXmlSignatureRule;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.initializeSecurityPolicy;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeArtifactResolve;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAuthnRequest;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runDecoder;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runEncoder;
import static org.opensaml.common.xml.SAMLConstants.SAML20P_NS;
import static org.opensaml.common.xml.SAMLConstants.SAML2_REDIRECT_BINDING_URI;
import static org.opensaml.common.xml.SAMLConstants.SAML2_SOAP11_BINDING_URI;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.collect.Maps;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.http.HttpClientUtil;
import com.google.enterprise.secmgr.http.HttpExchange;
import com.google.enterprise.secmgr.saml.HttpExchangeToInTransport;
import com.google.enterprise.secmgr.saml.HttpExchangeToOutTransport;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.SamlSharedData;

import java.io.ObjectInputStream;
import java.io.Serializable;
import java.net.URI;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPSOAP11Decoder;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.binding.encoding.HTTPSOAP11Encoder;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.SSODescriptor;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.security.MetadataCredentialResolver;
import org.opensaml.security.MetadataCriteria;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.util.URLBuilder;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.security.SecurityPolicyException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.criteria.UsageCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.util.Pair;
import org.opensaml.xml.validation.ValidationException;

import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A library implementing most of the functionality of a SAML Service Provider
 * using the Web Browser SSO Profile.  This library knows how to send an
 * authentication request via the HTTP Redirect binding, and to receive a
 * response via either HTTP Artifact or POST binding.
 */
@ThreadSafe
@ParametersAreNonnullByDefault
public final class SamlAuthnClient implements Serializable {
  private static final String SM_PROVIDER_NAME = "Google Enterprise Security Manager";
  private static final Object REQUEST_ID_LOCK = new Object();
  private static final Logger logger = Logger.getLogger(SamlAuthnClient.class.getName());

  /**
   * A default value for timeout parameters.  When given, we use HttpClient's
   * internal default timeout.
   */
  public static final int DEFAULT_TIMEOUT = -1;

  @Nonnull transient private Metadata metadata;
  @Nonnull private final String peerEntityId;
  @Nonnull transient private SamlSharedData sharedData;
  private final int timeout;
  private final URI metadataUri;

  @GuardedBy("REQUEST_ID_LOCK") private String requestId;

  private SamlAuthnClient(Metadata metadata, String peerEntityId, SamlSharedData sharedData,
      int timeout, URI metadataUri) {
    this.metadata = metadata;
    this.peerEntityId = peerEntityId;
    this.sharedData = sharedData;
    this.timeout = timeout;
    this.metadataUri = metadataUri;
  }

  /**
   * Creates an instance of the authentication client library.
   *
   * @param metadata Metadata to use when encoding and decoding messages.
   * @param peerEntityId The entity ID of the peer.
   * @param sharedData A shared-data object to supply signing credential, etc.
   * @param timeout An HTTP socket timeout value in milliseconds.  Zero means no
   *        timeout; {@link #DEFAULT_TIMEOUT} means to use the HttpClient
   *        default timeout.  Otherwise the timeout must be a positive value.
   * @return An instance that uses the given parameters.
   */
  @Nonnull
  public static SamlAuthnClient make(Metadata metadata, String peerEntityId,
      SamlSharedData sharedData, int timeout, URI metadataUri) {
    Preconditions.checkNotNull(metadata);
    Preconditions.checkNotNull(peerEntityId);
    Preconditions.checkNotNull(sharedData);
    Preconditions.checkArgument(sharedData.getRole() == SamlSharedData.Role.SERVICE_PROVIDER);
    Preconditions.checkArgument(timeout >= 0 || timeout == DEFAULT_TIMEOUT);
    return new SamlAuthnClient(metadata, peerEntityId, sharedData, timeout, metadataUri);
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
   * Gets the metadata for this client's local entity.
   *
   * @return The entity descriptor for the local entity.
   */
  @Nonnull
  public EntityDescriptor getLocalEntity()
      throws IOException {
    return metadata.getEntity(getLocalEntityId());
  }

  /**
   * Gets the metadata for this client's peer entity.
   *
   * @return The entity descriptor for the peer entity.
   */
  @Nonnull
  public EntityDescriptor getPeerEntity()
      throws IOException {
    return metadata.getEntity(peerEntityId);
  }

  /**
   * Gets the message ID of the most recent request.
   *
   * @return The message ID of the most recent request.
   * @throws IllegalStateException if called prior to any request.
   */
  @Nonnull
  public String getRequestId() {
    synchronized (REQUEST_ID_LOCK) {
      Preconditions.checkState(requestId != null);
      return requestId;
    }
  }

  /**
   * Gets the metadata for this client's local assertion consumer service.
   *
   * @param binding A SAML binding that the service must use.
   *     ({@link SAMLConstants} has definitions for all the standard bindings.)
   * @return An assertion consumer service descriptor.
   * @throws IllegalArgumentException if there's no appropriate service.
   */
  @Nonnull
  public AssertionConsumerService getAssertionConsumerService(String binding)
      throws IOException {
    SPSSODescriptor role = getLocalEntity().getSPSSODescriptor(SAML20P_NS);
    for (AssertionConsumerService acs : role.getAssertionConsumerServices()) {
      if (binding.equals(acs.getBinding())) {
        return acs;
      }
    }
    throw new IllegalArgumentException("No assertion consumer with binding " + binding);
  }

  /**
   * Sends an AuthnRequest message to the IdP via the redirect protocol.
   *
   * @param response An HTTP response message that will be filled with the encoded redirect.
   * @param decorator A log-message decorator.
   * @throws IOException if there are I/O errors while sending the message.
   */
  public void sendAuthnRequest(HttpServletResponse response, Decorator decorator)
      throws IOException {
    SAMLMessageContext<SAMLObject, AuthnRequest, NameID> context
        = sharedData.makeSamlMessageContext(metadata);
    sharedData.initializePeerEntity(context, peerEntityId,
        SingleSignOnService.DEFAULT_ELEMENT_NAME,
        SAML2_REDIRECT_BINDING_URI);
    if (context.getPeerEntityEndpoint() == null) {
      throw new IllegalArgumentException("Peer entity endpoint is null for :"
                                          + context.getPeerEntityId());
    }
    // Generate the request
    AuthnRequest authnRequest =
        makeAuthnRequest(context.getOutboundMessageIssuer(), new DateTime());
    authnRequest.setProviderName(SM_PROVIDER_NAME);
    authnRequest.setIsPassive(false); 
    authnRequest.setDestination(context.getPeerEntityEndpoint().getLocation());

    // If we're signing the request, set up dynamic service pointers.
    if (context.getOuboundSAMLMessageSigningCredential() != null) {
      SPSSODescriptor sp = (SPSSODescriptor) context.getLocalEntityRoleMetadata();
      List<AssertionConsumerService> services = sp.getAssertionConsumerServices();
      AssertionConsumerService foundService = null;

      SSODescriptor idp = (SSODescriptor) context.getPeerEntityRoleMetadata();
      if (idp != null && !idp.getArtifactResolutionServices().isEmpty()) {
        for (AssertionConsumerService service : services) {
          if (service.getBinding().equals(SAML_BINDING_HTTP_ARTIFACT)) {
            foundService = service;
            break;
          }
        }
      } else {
        for (AssertionConsumerService service : services) {
          if (service.getBinding().equals(SAML_BINDING_HTTP_POST)) {
            foundService = service;
            break;
          }
        }
      }

      // The assertion consumer services are defined in
      // secmgr/data/saml-metadata.xml.
      // The default is post binding.
      if (foundService == null) {
        // Normally shouldn't get here.
        foundService = sp.getDefaultAssertionConsumerService();
      }

      authnRequest.setAssertionConsumerServiceURL(foundService.getLocation());
      authnRequest.setProtocolBinding(foundService.getBinding());
    }

    logger.fine("binding " + authnRequest.getProtocolBinding());
    context.setOutboundSAMLMessage(authnRequest);

    // Remember the request ID for later.
    synchronized (REQUEST_ID_LOCK) {
      requestId = authnRequest.getID();
    }

    // Not needed:
    //context.setRelayState();

    // Send the request via redirect to the user agent
    ServletBase.initResponse(response);
    context.setOutboundMessageTransport(new HttpServletResponseAdapter(response, true));
    runEncoder(new RedirectEncoder(), context, decorator);
  }

  /**
   * Decodes a SSO response.
   *
   * @param request An HTTP request containing the encoded response.
   * @param binding The SAML binding that was used to transport the request.
   * @return The decoded response.
   * @throws IOException if there are I/O errors while decoding the message.
   * @throws SecurityException if the decoded message violates the security policy.
   * @throws IllegalArgumentException if the binding isn't supported.
   */
  @Nonnull
  public Response decodeResponse(HttpServletRequest request, String binding)
      throws IOException, SecurityException {
    if (SAMLConstants.SAML2_POST_BINDING_URI.equals(binding)) {
      return decodePostResponse(request);
    } else if (SAMLConstants.SAML2_ARTIFACT_BINDING_URI.equals(binding)) {
      return decodeArtifactResponse(request);
    } else {
      throw new IllegalArgumentException("Unsupported SAML binding: " + binding);
    }
  }

  private Response decodePostResponse(HttpServletRequest request)
      throws IOException, SecurityException {
    Decorator decorator = SessionUtil.getLogDecorator(request);
    SAMLMessageContext<Response, SAMLObject, NameID> context
        = sharedData.makeSamlMessageContext(metadata);
    initializeSecurityPolicy(context,
        getMandatoryIssuerRule(),
        getXmlSignatureRule(),
        getMandatoryAuthenticatedMessageRule());
    sharedData.initializePeerEntity(context, peerEntityId,
        SingleSignOnService.DEFAULT_ELEMENT_NAME,
        SAML2_REDIRECT_BINDING_URI);

    boolean responseFromAuthnIssuer = false;
    context.setInboundMessageTransport(new HttpServletRequestAdapter(request));
    try {
      // Two major things are done in all decoders extending
      // org.opensaml.ws.message.decoder.BaseMessageDecoder#decode():
      //
      // 1. Do decoding. Various decoders can deal with different SAML message bindings, including
      //    HTTP POST, HTTP Artifact, SOAP 11, etc. Various decoders can (must) override doDecode().
      //
      // 2. Process security policy. BaseMessageDecoder#processSecurityPolicy provides the default
      //    implementation of that, and children classes usually don't override it.
      //
      // SecurityException will only be thrown by processSecurityPolicy, which means the decoding
      // has been done without throwing exceptions. Note, not throwing exception during decoding
      // doesn't mean the inbound SAML message is not null. It depends on concrete decoder's
      // implementation.
      //
      // So, with this said, here, we are dependent on PARTIAL results of running the decoder.
      // However, catching SecurityException is a good enough indicator of failing verifying the
      // entire Response and indicator of continuing verifying Assertion if extracted Response is
      // not null.
      runDecoder(new HTTPPostDecoder(getBasicParserPool()), context, decorator,
          Response.DEFAULT_ELEMENT_NAME);
      responseFromAuthnIssuer = true;
    } catch (SecurityPolicyException e) {
      // Fine. Go check assertions.
      logger.log(Level.FINE,
          "Get SecurityPolicyException in decoding response. Continue with"
          + " checking whether there is verified and trusted assertion.", e);
    }
    Response samlResponse = context.getInboundSAMLMessage();
    if (samlResponse == null) {
      throw new IOException("Decoded SAML response is null");
    }

    if (responseFromAuthnIssuer) {
      return samlResponse;
    }

    if (null == findValidAssertion(samlResponse)) {
      throw new SecurityPolicyException("No assertion from authenticated issuer!");
    }

    return samlResponse;
  }

  // Here we assume the first (if there is one) verified assertion is the first valid assertion by
  // definition at {@link ResponseParser#isAssertionValid}.
  // Otherwise, we might have security risk, that is, we might trust valid but un-verified
  // assertion. Consider addressing this in a later CL if it's desired. In most customer cases, a
  // response should contain only one assertion.
  private Assertion findValidAssertion(Response samlResponse) throws IOException {
    if (samlResponse == null) {
      return null;
    }

    for (Assertion assertion : samlResponse.getAssertions()) {
      if (verifySignatureBasedOnMetadata(assertion)) {
        return assertion;
      }
    }
    return null;
  }

  private boolean verifySignatureBasedOnMetadata(Assertion assertion) {
    return verifySignatureBasedOnMetadataInternal(assertion, metadata.getProvider());
  }

  @VisibleForTesting
  static boolean verifySignatureBasedOnMetadataInternal(Assertion assertion,
      MetadataProvider mdProvider) {
    Signature sig = assertion.getSignature();
    if (sig == null) {
      // no signature attached
      return false;
    }

    // Validator and criteriaSet don't need to be created over and over, but these are light-weight
    // objects and also in most cases, one Response contains only one assertion, so just let them be
    // created.
    SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
    try {
      validator.validate(sig);
    } catch (ValidationException e) {
      // Quoted from https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUserManJavaDSIG
      //
      // In order to prevent certain types of denial-of-service attacks associated with signature
      // verification, it is advisable to successfully validate the Signature with the
      // org.opensaml.security.SAMLSignatureProfileValidator prior to attempting to
      // cryptographically verify the signature.
      logger.warning("Signature fails to be validated");
      return false;
    }

    // Verifying a Signature with SAML 2 Metadata Information
    MetadataCredentialResolver mdResolver = new MetadataCredentialResolver(mdProvider);
    KeyInfoCredentialResolver keyInfoCredResolver =
        Configuration.getGlobalSecurityConfiguration().getDefaultKeyInfoCredentialResolver();
    ExplicitKeySignatureTrustEngine engine =
        new ExplicitKeySignatureTrustEngine(mdResolver, keyInfoCredResolver);
    CriteriaSet criteriaSet = new CriteriaSet();
    criteriaSet.add(new EntityIDCriteria(assertion.getIssuer().getValue()));
    criteriaSet.add(new MetadataCriteria(IDPSSODescriptor.DEFAULT_ELEMENT_NAME,
          SAMLConstants.SAML20P_NS));
    criteriaSet.add(new UsageCriteria(UsageType.SIGNING));

    boolean validated = false;
    try {
      if (engine.validate(sig, criteriaSet)) {
        logger.fine("Successfully verified an assertion");
        validated = true;
      }
    } catch (SecurityException e) {
      logger.log(
          Level.WARNING, "SecurityException during validating signature via TrustEngine", e);
    }
    if (!validated) {
      logger.warning(
          "Signature was either invalid or signing key could not be established as trusted");
    }
    return validated;
  }

  private Response decodeArtifactResponse(HttpServletRequest request)
      throws IOException, SecurityException {
    Decorator decorator = SessionUtil.getLogDecorator(request);
    try {
      return resolveArtifact(request, getArtifact(request), decorator);
    } catch (MessageDecodingException e) {
      throw new IOException(e);
    }
  }

  private String getArtifact(HttpServletRequest request)
      throws MessageDecodingException {
    // The OpenSAML HTTPArtifactDecoder isn't implemented, so we must manually decode the
    // artifact.
    String artifact = request.getParameter("SAMLart");
    if (artifact == null) {
      throw new MessageDecodingException("No artifact in message");
    }
    return artifact;
  }

  private Response resolveArtifact(HttpServletRequest request, String artifact,
      Decorator decorator)
      throws IOException, SecurityException, MessageDecodingException {
    // Establish the SAML message context.
    SAMLMessageContext<ArtifactResponse, ArtifactResolve, NameID> context
        = sharedData.makeSamlMessageContext(metadata);
    sharedData.initializePeerEntity(context, peerEntityId,
        ArtifactResolutionService.DEFAULT_ELEMENT_NAME,
        SAML2_SOAP11_BINDING_URI);

    // Generate the request.
    context.setOutboundSAMLMessage(
        makeArtifactResolve(sharedData.getLocalEntityId(), new DateTime(), artifact));

    // Encode the request.
    HttpExchange exchange
        = HttpClientUtil.postExchange(new URL(context.getPeerEntityEndpoint().getLocation()), null);
    try {

      HttpExchangeToOutTransport out = new HttpExchangeToOutTransport(exchange);
      try {
        context.setOutboundMessageTransport(out);
        context.setRelayState(request.getParameter("RelayState"));
        runEncoder(new HTTPSOAP11Encoder(), context, decorator);
      } finally {
        out.finish();
      }

      exchange.setTimeout(timeout);

      // Do HTTP exchange.
      int status = exchange.exchange();
      if (status != HttpServletResponse.SC_OK) {
        throw new IOException("Incorrect HTTP status: " + status);
      }

      initializeSecurityPolicy(context,
          getMandatoryIssuerRule(),
          getXmlSignatureRule());

      // Decode the response.
      context.setInboundMessageTransport(new HttpExchangeToInTransport(exchange));
      runDecoder(new HTTPSOAP11Decoder(getBasicParserPool()), context, decorator,
          ArtifactResponse.DEFAULT_ELEMENT_NAME);

    } finally {
      exchange.close();
    }

    // Return the decoded response.
    ArtifactResponse artifactResponse = context.getInboundSAMLMessage();
    if (artifactResponse == null) {
      throw new MessageDecodingException("Decoded SAML response is null");
    }
    Response samlResponse = (Response) artifactResponse.getMessage();
    if (samlResponse == null) {
      throw new MessageDecodingException("Unable to resolve artifact");
    }
    return samlResponse;
  }

  /**
   * A tweaked redirect encoder that preserves query parameters from the endpoint URL.
   */
  private static final class RedirectEncoder extends HTTPRedirectDeflateEncoder {

    RedirectEncoder() {
      super();
    }

    @Override
    protected String buildRedirectURL(@SuppressWarnings("rawtypes") SAMLMessageContext context,
        String endpointUrl, String message)
        throws MessageEncodingException {
      String encodedUrl = super.buildRedirectURL(context, endpointUrl, message);

      // Get the query parameters from the endpoint URL.
      List<Pair<String, String>> endpointParams = new URLBuilder(endpointUrl).getQueryParams();
      if (endpointParams.isEmpty()) {
        // If none, we're finished.
        return encodedUrl;
      }

      URLBuilder builder = new URLBuilder(encodedUrl);
      List<Pair<String, String>> samlParams = builder.getQueryParams();

      // Merge the endpoint params with the SAML params.
      Map<String, String> params = Maps.newHashMap();
      for (Pair<String, String> entry : endpointParams) {
        params.put(entry.getFirst(), entry.getSecond());
      }
      for (Pair<String, String> entry : samlParams) {
        params.put(entry.getFirst(), entry.getSecond());
      }

      // Copy the merged params back into the result.
      samlParams.clear();
      for (Map.Entry<String, String> entry : params.entrySet()) {
        samlParams.add(new Pair<String, String>(entry.getKey(), entry.getValue()));
      }
      return builder.buildURL();
    }
  }

  private void readObject(ObjectInputStream is)
      throws ClassNotFoundException, IOException {
    is.defaultReadObject();
    this.metadata = Metadata.getInstance(metadataUri);
    this.sharedData = SamlSharedData.getProductionInstance(SamlSharedData.Role.SERVICE_PROVIDER);
  }

}
