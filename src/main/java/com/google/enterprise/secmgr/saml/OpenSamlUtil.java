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

package com.google.enterprise.secmgr.saml;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.saml.Metadata.GsaFilesystemMetadataResolver;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import net.shibboleth.utilities.java.support.security.IdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.security.SecureRandomIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.messaging.context.BaseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecoder;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.MessageEncoder;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.handler.impl.BasicMessageHandlerChain;
import org.opensaml.messaging.handler.impl.CheckMandatoryAuthentication;
import org.opensaml.messaging.handler.impl.CheckMandatoryIssuer;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.saml.common.binding.artifact.impl.BasicSAMLArtifactMap;
import org.opensaml.saml.common.binding.impl.SAMLOutboundDestinationHandler;
import org.opensaml.saml.common.binding.security.impl.SAMLOutboundProtocolMessageSigningHandler;
import org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.PredicateRoleDescriptorResolver;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.binding.security.impl.SAML2AuthnRequestsSignedSecurityHandler;
import org.opensaml.saml.saml2.binding.security.impl.SAML2HTTPRedirectDeflateSignatureSecurityHandler;
import org.opensaml.saml.saml2.core.Action;
import org.opensaml.saml.saml2.core.Artifact;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.AuthzDecisionQuery;
import org.opensaml.saml.saml2.core.AuthzDecisionStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.DecisionTypeEnumeration;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Statement;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.saml.security.impl.MetadataCredentialResolver;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.impl.ChainingCredentialResolver;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.security.trust.TrustEngine;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.config.GlobalSecurityConfigurationInitializer;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCriterion;
import org.opensaml.xmlsec.keyinfo.impl.BasicProviderKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.KeyInfoProvider;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.impl.provider.DSAKeyValueProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.InlineX509DataProvider;
import org.opensaml.xmlsec.keyinfo.impl.provider.RSAKeyValueProvider;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Element;

/**
 * A collection of utilities to support OpenSAML programming.  The majority of the
 * definitions here are static factory methods for SAML objects.
 *
 * <p><strong>Notes on security policies and credential resolution:</strong>
 *
 * <p>OpenSAML has a very complicated mechanism for dealing with credentials and
 * trust, of which we use only a small part.  Here are the basic components:
 *
 * <dl>
 * <dt>{@link Credential}
 * <dd>Some information that can be used for signing or encryption.
 *
 * <dt>{@link CredentialResolver}
 * <dd>Selects one or more credentials based on a set of criteria.
 *
 * <dt>{@link KeyInfoCredentialResolver}
 * <dd>Extracts one or more credentials from a {@link KeyInfo} element; it's allowed to
 * choose between different credentials based on internal criteria.  We currently use a
 * KeyInfoCredentialResolver that selects only X.509 certificate credentials.
 *
 * <dt>{@link TrustEngine}
 * <dd>Evaluates the trustworthiness and validity of a given object against some given
 * criteria.  It is used as an element of some policy rules.
 *
 * <p>The programmer simply attaches a security-policy resolver to the SAML
 * message context and OpenSAML will automatically enforce the security policy
 * as appropriate.
 */
@Immutable
@ParametersAreNonnullByDefault
public final class OpenSamlUtil {
  private static final Logger logger = Logger.getLogger(OpenSamlUtil.class.getName());

  /**
   * The human-readable name of the (GSA) service provider.
   */
  public static final String GOOGLE_PROVIDER_NAME = "Google Search Appliance";

  /**
   * The human-readable name of the (Security Manager) service provider.
   */
  public static final String SM_PROVIDER_NAME = "Google Security Manager";

  /**
   * The SAML "bearer" method, normally used in SubjectConfirmation.
   */
  public static final String BEARER_METHOD = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

  public static final QName SAML_ISSUER_TAG
      = new QName(SAMLConstants.SAML20_NS, "Issuer", SAMLConstants.SAML20_PREFIX);

  public static final QName SAML_SIGNATURE_TAG
      = new QName("http://www.w3.org/2000/09/xmldsig#", "Signature", "ds");

  public static final QName SAML_EXTENSIONS_TAG = Extensions.DEFAULT_ELEMENT_NAME;

  public static final String GOOGLE_NS_URI = "http://www.google.com/";
  public static final String GOOGLE_NS_PREFIX = "goog";
  public static String defaultDateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

  private static final boolean ACCEPT_DTD;

  static {
    ACCEPT_DTD = Boolean.parseBoolean(System.getProperty("gsa.acceptDTDInSamlResponse"));

    try {
      InitializationService.initialize();
      new GlobalSecurityConfigurationInitializer().init();
    } catch (InitializationException e) {
      throw new IllegalStateException(e);
    }

    // This is required in order to patch around missing code in OpenSAML.
    XMLObjectProviderRegistrySupport.registerObjectProvider(
        AttributeValue.DEFAULT_ELEMENT_NAME,
        new AttributeValueBuilder(),
        new AttributeValueMarshaller(),
        new AttributeValueUnmarshaller());
    XMLObjectProviderRegistrySupport.registerObjectProvider(
        GsaAuthn.DEFAULT_ELEMENT_NAME,
        new GsaAuthnBuilder(),
        new GsaAuthnMarshaller(),
        new GsaAuthnUnmarshaller());
    XMLObjectProviderRegistrySupport.registerObjectProvider(
        GsaAuthz.DEFAULT_ELEMENT_NAME,
        new GsaAuthzBuilder(),
        new GsaAuthzMarshaller(),
        new GsaAuthzUnmarshaller());
    XMLObjectProviderRegistrySupport.registerObjectProvider(
        Resource.DEFAULT_ELEMENT_NAME,
        new ResourceBuilder(),
        new ResourceMarshaller(),
        new ResourceUnmarshaller());
    XMLObjectProviderRegistrySupport.registerObjectProvider(
        Group.DEFAULT_ELEMENT_NAME,
        new GroupBuilder(),
        new GroupMarshaller(),
        new GroupUnmarshaller());
    XMLObjectProviderRegistrySupport.registerObjectProvider(
        SecmgrCredential.DEFAULT_ELEMENT_NAME,
        new SecmgrCredentialBuilder(),
        new SecmgrCredentialMarshaller(),
        new SecmgrCredentialUnmarshaller());
  }

  private static final XMLObjectBuilderFactory objectBuilderFactory =
      XMLObjectProviderRegistrySupport.getBuilderFactory();

  // TODO: @SuppressWarnings is needed because objectBuilderFactory.getBuilder() returns a
  // supertype of the actual type.
  @SuppressWarnings("unchecked")
  static <T extends SAMLObject> SAMLObjectBuilder<T> makeSamlObjectBuilder(QName name) {
    return (SAMLObjectBuilder<T>) objectBuilderFactory.getBuilder(name);
  }

  private static final SAMLObjectBuilder<Action> actionBuilder =
      makeSamlObjectBuilder(Action.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<Artifact> artifactBuilder =
      makeSamlObjectBuilder(Artifact.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<ArtifactResolve> artifactResolveBuilder =
      makeSamlObjectBuilder(ArtifactResolve.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<ArtifactResponse> artifactResponseBuilder =
      makeSamlObjectBuilder(ArtifactResponse.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<Assertion> assertionBuilder =
      makeSamlObjectBuilder(Assertion.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<AssertionConsumerService> assertionConsumerServiceBuilder =
      makeSamlObjectBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<Attribute> attributeBuilder =
      makeSamlObjectBuilder(Attribute.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder =
      makeSamlObjectBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<AttributeValue> attributeValueBuilder =
      makeSamlObjectBuilder(AttributeValue.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<Audience> audienceBuilder =
      makeSamlObjectBuilder(Audience.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder =
      makeSamlObjectBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<AuthnContext> authnContextBuilder =
      makeSamlObjectBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder =
      makeSamlObjectBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<AuthnRequest> authnRequestBuilder =
      makeSamlObjectBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<AuthnStatement> authnStatementBuilder =
      makeSamlObjectBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<AuthzDecisionQuery> authzDecisionQueryBuilder =
      makeSamlObjectBuilder(AuthzDecisionQuery.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<AuthzDecisionStatement> authzDecisionStatementBuilder =
      makeSamlObjectBuilder(AuthzDecisionStatement.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<Conditions> conditionsBuilder =
      makeSamlObjectBuilder(Conditions.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<Extensions> extensionsBuilder =
      makeSamlObjectBuilder(Extensions.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<Issuer> issuerBuilder =
      makeSamlObjectBuilder(Issuer.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<NameID> nameIDBuilder =
      makeSamlObjectBuilder(NameID.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<Response> responseBuilder =
      makeSamlObjectBuilder(Response.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<Status> statusBuilder =
      makeSamlObjectBuilder(Status.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<StatusCode> statusCodeBuilder =
      makeSamlObjectBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<StatusMessage> statusMessageBuilder =
      makeSamlObjectBuilder(StatusMessage.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<Subject> subjectBuilder =
      makeSamlObjectBuilder(Subject.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder =
      makeSamlObjectBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder =
      makeSamlObjectBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);

  private static final SAMLObjectBuilder<GsaAuthn> gsaAuthnBuilder =
      makeSamlObjectBuilder(GsaAuthn.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<GsaAuthz> gsaAuthzBuilder =
      makeSamlObjectBuilder(GsaAuthz.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<Resource> resourceBuilder =
      makeSamlObjectBuilder(Resource.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<Group> groupBuilder =
      makeSamlObjectBuilder(Group.DEFAULT_ELEMENT_NAME);
  private static final SAMLObjectBuilder<SecmgrCredential> credentialBuilder =
      makeSamlObjectBuilder(SecmgrCredential.DEFAULT_ELEMENT_NAME);

  // Metadata builders

  private static final SAMLObjectBuilder<SingleSignOnService> singleSignOnServiceBuilder =
      makeSamlObjectBuilder(SingleSignOnService.DEFAULT_ELEMENT_NAME);

  // Identifier generator
  private static final IdentifierGenerationStrategy idGenerator =
      new SecureRandomIdentifierGenerationStrategy();

  // Non-instantiable class.
  private OpenSamlUtil() {
  }

  private static void initializeRequest(RequestAbstractType request, String issuer,
      DateTime issueInstant) {
    request.setID(generateIdentifier());
    request.setVersion(SAMLVersion.VERSION_20);
    request.setIssuer(makeIssuer(issuer));
    request.setIssueInstant(issueInstant);
  }

  private static void initializeResponse(StatusResponseType response, String issuer,
      DateTime issueInstant, Status status, String inResponseTo) {
    response.setID(generateIdentifier());
    response.setVersion(SAMLVersion.VERSION_20);
    response.setIssuer(makeIssuer(issuer));
    response.setIssueInstant(issueInstant);
    response.setStatus(status);
    response.setInResponseTo(inResponseTo);
  }

  /**
   * Static factory for SAML {@link Action} objects.
   *
   * @param name A URI identifying the represented action.
   * @param namespace A URI identifying the class of names being specified.
   * @return A new <code>Action</code> object.
   */
  public static Action makeAction(String name, String namespace) {
    Action action = actionBuilder.buildObject();
    action.setAction(name);
    action.setNamespace(namespace);
    return action;
  }

  /**
   * Static factory for SAML {@link Artifact} objects.
   *
   * @param value The artifact string.
   * @return A new <code>Artifact</code> object.
   */
  private static Artifact makeArtifact(String value) {
    Artifact element = artifactBuilder.buildObject();
    element.setArtifact(value);
    return element;
  }

  /**
   * Static factory for SAML {@link ArtifactResolve} objects.
   *
   * @param issuer The entity issuing this request.
   * @param issueInstant The time of issue for this statement.
   * @param value The artifact string to be resolved.
   * @return A new <code>ArtifactResolve</code> object.
   */
  public static ArtifactResolve makeArtifactResolve(String issuer, DateTime issueInstant,
      String value) {
    ArtifactResolve request = artifactResolveBuilder.buildObject();
    initializeRequest(request, issuer, issueInstant);
    request.setArtifact(makeArtifact(value));
    return request;
  }

  /**
   * Static factory for SAML {@link ArtifactResponse} objects.
   *
   * @param issuer The entity issuing this response.
   * @param issueInstant The time of issue for this statement.
   * @param status The <code>Status</code> object indicating the success of the resolution.
   * @param inResponseTo The message ID of the request this is a response to.
   * @param message The embedded message.
   * @return A new <code>ArtifactResponse</code> object.
   */
  public static ArtifactResponse makeArtifactResponse(String issuer, DateTime issueInstant,
      Status status, String inResponseTo, SAMLObject message) {
    ArtifactResponse response = artifactResponseBuilder.buildObject();
    initializeResponse(response, issuer, issueInstant, status, inResponseTo);
    if (message != null) {
      response.setMessage(message);
    }
    return response;
  }

  /**
   * Static factory for SAML {@link Assertion} objects.
   *
   * @param issuer The entity issuing this assertion.
   * @param issueInstant The time of issue for this statement.
   * @param subject The subject of the assertion.
   * @param conditions The conditions under which this assertion is valid.
   * @param statements The statements being made by this assertion.
   * @return A new {@code Assertion} object.
   */
  public static Assertion makeAssertion(String issuer, DateTime issueInstant, Subject subject,
      @Nullable Conditions conditions, Iterable<? extends Statement> statements) {
    Assertion assertion = assertionBuilder.buildObject();
    assertion.setID(generateIdentifier());
    assertion.setVersion(SAMLVersion.VERSION_20);
    assertion.setIssuer(makeIssuer(issuer));
    assertion.setIssueInstant(issueInstant);
    assertion.setSubject(subject);
    if (conditions != null) {
      assertion.setConditions(conditions);
    }
    for (Statement statement : statements) {
      if (statement instanceof AuthnStatement) {
        assertion.getAuthnStatements().add((AuthnStatement) statement);
      } else if (statement instanceof AuthzDecisionStatement) {
        assertion.getAuthzDecisionStatements().add((AuthzDecisionStatement) statement);
      } else if (statement instanceof AttributeStatement) {
        assertion.getAttributeStatements().add((AttributeStatement) statement);
      } else {
        throw new IllegalArgumentException("Unknown statement type: " + statement);
      }
    }
    return assertion;
  }

  /**
   * Static factory for SAML {@link Assertion} objects.
   *
   * @param issuer The entity issuing this assertion.
   * @param issueInstant The time of issue for this statement.
   * @param subject The subject of the assertion.
   * @param conditions The conditions under which this assertion is valid.
   * @param statement The statement being made by this assertion.
   * @return A new {@code Assertion} object.
   */
  public static Assertion makeAssertion(String issuer, DateTime issueInstant, Subject subject,
      Conditions conditions, Statement statement) {
    return makeAssertion(issuer, issueInstant, subject, conditions, ImmutableList.of(statement));
  }

  /**
   * Static factory for SAML {@link AssertionConsumerService} objects.
   *
   * @param location A URL for this service.
   * @param binding A SAML binding used to communicate with the service.
   * @return A new {@code AssertionConsumerService} object.
   */
  @Nonnull
  public static AssertionConsumerService makeAssertionConsumerService(String location,
      String binding) {
    Preconditions.checkNotNull(location);
    Preconditions.checkNotNull(binding);
    AssertionConsumerService endpoint = assertionConsumerServiceBuilder.buildObject();
    endpoint.setLocation(location);
    endpoint.setBinding(binding);
    endpoint.setIndex(0);
    endpoint.setIsDefault(true);
    return endpoint;
  }

  /**
   * Static factory for SAML {@link Attribute} objects.
   *
   * @param name The attribute name.
   * @return A new <code>Attribute</code> object.
   */
  public static Attribute makeAttribute(String name) {
    Attribute attribute = attributeBuilder.buildObject();
    attribute.setName(name);
    return attribute;
  }

  /**
   * Static factory for SAML {@link AttributeStatement} objects.
   *
   * @param attributes The attributes to include in the statement.
   * @return A new <code>AttributeStatement</code> object.
   */
  public static AttributeStatement makeAttributeStatement(Attribute... attributes) {
    AttributeStatement statement = attributeStatementBuilder.buildObject();
    for (Attribute attribute : attributes) {
      if (attribute != null) {
        statement.getAttributes().add(attribute);
      }
    }
    return statement;
  }

  /**
   * Static factory for SAML {@link AttributeValue} objects.
   *
   * @return A new <code>AttributeValue</code> object.
   */
  public static AttributeValue makeAttributeValue(String value) {
    AttributeValue attrValue = attributeValueBuilder.buildObject();
    attrValue.setValue(value);
    return attrValue;
  }

  /**
   * Static factory for SAML {@link Audience} objects.
   *
   * @param uri The audience URI.
   * @return A new <code>Audience</code> object.
   */
  private static Audience makeAudience(String uri) {
    Audience audience = audienceBuilder.buildObject();
    audience.setAudienceURI(uri);
    return audience;
  }

  /**
   * Static factory for SAML {@link AudienceRestriction} objects.
   *
   * @param uris The audience URIs.
   * @return A new <code>AudienceRestriction</code> object.
   */
  public static AudienceRestriction makeAudienceRestriction(String... uris) {
    AudienceRestriction restriction = audienceRestrictionBuilder.buildObject();
    for (String uri : uris) {
      restriction.getAudiences().add(makeAudience(uri));
    }
    return restriction;
  }

  /**
   * Static factory for SAML {@link AuthnContext} objects.
   *
   * @param classRef An <code>AuthnContextClassRef</code> identifying an authentication context
   * class.
   * @return A new <code>AuthnContext</code> object.
   */
  private static AuthnContext makeAuthnContext(AuthnContextClassRef classRef) {
    AuthnContext context = authnContextBuilder.buildObject();
    context.setAuthnContextClassRef(classRef);
    return context;
  }

  /**
   * Static factory for SAML {@link AuthnContext} objects.
   *
   * A convenience method that wraps the given URI in an {@link AuthnContextClassRef} object.
   *
   * @param uri A URI identifying an authentication context class.
   * @return A new <code>AuthnContext</code> object.
   */
  private static AuthnContext makeAuthnContext(String uri) {
    return makeAuthnContext(makeAuthnContextClassRef(uri));
  }

  /**
   * Static factory for SAML {@link AuthnContextClassRef} objects.
   *
   * @param uri A URI identifying an authentication context class.
   * @return A new <code>AuthnContextClassRef</code> object.
   */
  private static AuthnContextClassRef makeAuthnContextClassRef(String uri) {
    AuthnContextClassRef classRef = authnContextClassRefBuilder.buildObject();
    classRef.setAuthnContextClassRef(uri);
    return classRef;
  }

  /**
   * Static factory for SAML {@link AuthnRequest} objects.
   *
   * @param issuer The entity issuing this request.
   * @param issueInstant The time of issue for this statement.
   * @return A new <code>AuthnRequest</code> object.
   */
  public static AuthnRequest makeAuthnRequest(String issuer, DateTime issueInstant) {
    AuthnRequest request = authnRequestBuilder.buildObject();
    initializeRequest(request, issuer, issueInstant);
    return request;
  }

  /**
   * Static factory for SAML {@link AuthnStatement} objects.
   *
   * @param issueInstant The time of issue for this statement.
   * @param uri A URI identifying an authentication context class.
   * @return A new <code>AuthnStatement</code> object.
   */
  public static AuthnStatement makeAuthnStatement(DateTime issueInstant, String uri) {
    AuthnStatement statement = authnStatementBuilder.buildObject();
    statement.setAuthnInstant(issueInstant);
    statement.setAuthnContext(makeAuthnContext(uri));
    return statement;
  }

  /**
   * Static factory for SAML {@link AuthzDecisionQuery} objects.
   *
   * @param issuer The entity issuing this query.
   * @param issueInstant The time of issue for this query.
   * @param subject The subject requesting access to a resource.
   * @param resource The resource for which access is being requested.
   * @param action The action on the resource for which access is being requested.
   * @return A new <code>AuthzDecisionQuery</code> object.
   */
  public static AuthzDecisionQuery makeAuthzDecisionQuery(String issuer, DateTime issueInstant,
      Subject subject, String resource, Action action) {
    AuthzDecisionQuery query = authzDecisionQueryBuilder.buildObject();
    initializeRequest(query, issuer, issueInstant);
    query.setSubject(subject);
    query.setResource(resource);
    query.getActions().add(action);
    return query;
  }

  /**
   * Static factory for SAML {@link AuthzDecisionStatement} objects.
   *
   * @param resource The resource referred to by this access decision.
   * @param decision The access decision made by the authorization service.
   * @param actions The actions authorized to perform on the stated resource.
   * @return A new <code>AuthzDecisionStatement</code> object.
   */
  public static AuthzDecisionStatement makeAuthzDecisionStatement(String resource,
      DecisionTypeEnumeration decision, Action... actions) {
    AuthzDecisionStatement statement = authzDecisionStatementBuilder.buildObject();
    statement.setResource(resource);
    statement.setDecision(decision);
    statement.getActions().addAll(Arrays.asList(actions));
    return statement;
  }

  /**
   * Static factory for SAML {@link Conditions} objects.
   *
   * @param notBefore Earliest time at which assertion is valid.
   * @param notOnOrAfter Latest time at which assertion is valid.
   * @param restriction The audience restriction that must be satisfied.
   * @return A new <code>Conditions</code> object.
   */
  public static Conditions makeConditions(DateTime notBefore, DateTime notOnOrAfter,
      AudienceRestriction restriction) {
    Conditions conditions = conditionsBuilder.buildObject();
    conditions.setNotBefore(notBefore);
    conditions.setNotOnOrAfter(notOnOrAfter);
    conditions.getAudienceRestrictions().add(restriction);
    return conditions;
  }

  /**
   * Static factory for SAML {@link Extensions} objects.
   *
   * @param children The child elements of the result.
   * @return A new {@code Extensions} object.
   */
  public static Extensions makeExtensions(Iterable<XMLObject> children) {
    Extensions extensions = extensionsBuilder.buildObject();
    for (XMLObject child : children) {
      child.setParent(extensions);
    }
    Iterables.addAll(extensions.getUnknownXMLObjects(), children);
    extensions
        .getNamespaceManager()
        .registerNamespaceDeclaration(new Namespace(GOOGLE_NS_URI, GOOGLE_NS_PREFIX));
    return extensions;
  }

  /**
   * Static factory for Google {@link GsaAuthn} extension objects.
   *
   * @param version A protocol version number.
   * @param sessionId A session ID.
   * @return A new {@code GsaAuthn} object.
   */
  public static GsaAuthn makeGsaAuthn(int version, String sessionId) {
    GsaAuthn gsaAuthn = gsaAuthnBuilder.buildObject();
    gsaAuthn.setVersion(version);
    gsaAuthn.setSessionId(sessionId);
    return gsaAuthn;
  }

  /**
   * Static factory for Google {@link GsaAuthz} extension objects.
   *
   * @param version A protocol version number.
   * @param mode An authorization mode.
   * @return A new {@code GsaAuthz} object.
   */
  public static GsaAuthz makeGsaAuthz(int version, GsaAuthz.Mode mode) {
    GsaAuthz gsaAuthz = gsaAuthzBuilder.buildObject();
    gsaAuthz.setVersion(version);
    gsaAuthz.setMode(mode);
    return gsaAuthz;
  }

  /**
   * Static factory for SAML {@link Issuer} objects.
   *
   * @param name The issuer of a response object.  In the absence of a specific format, this is a
   *     URI identifying the issuer.
   * @return A new <code>Issuer</code> object.
   */
  private static Issuer makeIssuer(String name) {
    Issuer issuer = issuerBuilder.buildObject();
    issuer.setValue(name);
    return issuer;
  }

  /**
   * Static factory for SAML {@link NameID} objects.
   *
   * @param name The name represented by this object.
   * @return A new <code>NameID</code> object.
   */
  private static NameID makeNameId(String name) {
    NameID id = nameIDBuilder.buildObject();
    id.setValue(name);
    return id;
  }

  /**
   * Static factory for Google {@link Resource} extension objects.
   *
   * @param uri A URI identifying the resource.
   * @param decision An authorization decision for the resource.
   * @param acl An ACL associated with the resource.
   * @return A new {@code Resource} object.
   */
  public static Resource makeResource(URI uri, @Nullable AuthzStatus decision,
      @Nullable String acl) {
    Resource resource = resourceBuilder.buildObject();
    resource.setUri(uri);
    resource.setDecision(decision);
    resource.setAcl(acl);
    return resource;
  }

  /**
   * Static factory for Google {@link Group} extension objects.
   *
   * @param name Name of group.
   * @param namespace Namespace of group.
   * @param domain Domain of group
   * @return A new {@code Group} object.
   */
  public static Group makeGroup(String name, String namespace,
      @Nullable String domain) {
    Group group = groupBuilder.buildObject();
    group.setName(name);
    group.setNamespace(namespace);
    group.setDomain(domain);
    return group;
  }

  public static List<Group> makeSamlGroupsFromIdentityGroups(
      Collection<com.google.enterprise.secmgr.identity.Group> groups) {
    List<Group> samlGroups = new ArrayList<Group>();
    for (com.google.enterprise.secmgr.identity.Group group : groups) {
      samlGroups.add(OpenSamlUtil.makeGroup(
          group.getName(),
          group.getNamespace(),
          group.getDomain()));
    }
    return samlGroups;
  }

  /**
   * Static factory for Google {@link Credential} extension objects.
   *
   * @param name Name of verified principal of this credential.
   * @param namespace Namespace of verified principal of this credential.
   * @param domain Domain of verified principal of this credential
   * @param password Password of verified principal of this credential
   * @param groups Verified groups of this credential
   * @return A new {@code Credential} object.
   */
  public static SecmgrCredential makeSecmgrCredential(String name, String namespace,
      @Nullable String domain, @Nullable String password, List<Group> groups) {
    SecmgrCredential cred = credentialBuilder.buildObject();
    cred.setName(name);
    cred.setNamespace(namespace);
    cred.setDomain(domain);
    cred.setPassword(password);
    cred.setGroups(groups);
    return cred;
  }

  /**
   * Static factory for SAML {@link Response} objects.
   *
   * @param issuer The entity issuing this response.
   * @param issueInstant The time of issue for this statement.
   * @param status The <code>Status</code> object indicating the success of requested action.
   * @param request The request that this is a response to.
   * @param assertions The assertions carried by this response.
   * @return A new <code>Response</code> object.
   */
  public static Response makeResponse(String issuer, DateTime issueInstant,
      Status status, RequestAbstractType request, Assertion... assertions) {
    return makeResponse(issuer, issueInstant, status, request.getID(), assertions);
  }

  /**
   * Static factory for SAML {@link Response} objects.
   *
   * @param issuer The entity issuing this response.
   * @param issueInstant The time of issue for this statement.
   * @param status The <code>Status</code> object indicating the success of requested action.
   * @param inResponseTo The message ID of the request this is a response to.
   * @param assertions The assertions carried by this response.
   * @return A new <code>Response</code> object.
   */
  public static Response makeResponse(String issuer, DateTime issueInstant, Status status,
      String inResponseTo, Assertion... assertions) {
    Response response = responseBuilder.buildObject();
    initializeResponse(response, issuer, issueInstant, status, inResponseTo);
    response.getAssertions().addAll(Arrays.asList(assertions));
    return response;
  }

  /**
   * Static factory for SAML {@link Status} objects.
   *
   * @param statusCode A status code indicating result status of a request.
   * @param statusMessage An optional message providing human-readable detail of the status.
   * @return A new {@link Status} object.
   */
  @Nonnull
  public static Status makeStatus(StatusCode statusCode, @Nullable StatusMessage statusMessage) {
    Preconditions.checkNotNull(statusCode);
    Status status = statusBuilder.buildObject();
    status.setStatusCode(statusCode);
    if (statusMessage != null) {
      status.setStatusMessage(statusMessage);
    }
    return status;
  }

  /**
   * Static factory for a successful SAML status element.
   *
   * @return A successful {@link Status} element.
   */
  @Nonnull
  public static Status makeSuccessfulStatus() {
    return makeStatus(makeStatusCode(StatusCode.SUCCESS), null);
  }

  /**
   * Static factory for a SAML status element representing an authentication failure.
   *
   * @return An authentication-failure {@link Status} element.
   */
  @Nonnull
  public static Status makeAuthnFailureStatus() {
    return makeStatus(
        makeStatusCode(StatusCode.RESPONDER, StatusCode.AUTHN_FAILED),
        makeStatusMessage("Authentication failed"));
  }

  /**
   * Static factory for a SAML status element representing a security failure.
   *
   * @param message A message to be included with the status.
   * @return A security-failure {@link Status} element.
   */
  @Nonnull
  public static Status makeSecurityFailureStatus(String message) {
    Preconditions.checkNotNull(message);
    return makeStatus(
        makeStatusCode(StatusCode.REQUESTER, StatusCode.REQUEST_DENIED),
        makeStatusMessage(message));
  }

  /**
   * Static factory for a SAML status element representing a responder failure.
   *
   * @param message A message to be included with the status.
   * @return A responder-failure {@link Status} element.
   */
  @Nonnull
  public static Status makeResponderFailureStatus(String message) {
    Preconditions.checkNotNull(message);
    return makeStatus(makeStatusCode(StatusCode.RESPONDER), makeStatusMessage(message));
  }

  /**
   * Static factory for a SAML status element representing a security failure.
   *
   * @return A security-failure {@link Status} element.
   */
  @Nonnull
  public static Status makeSecurityFailureStatus() {
    return makeStatus(makeStatusCode(StatusCode.REQUESTER, StatusCode.REQUEST_DENIED), null);
  }

  /**
   * Is the given status successful?
   *
   * @param status A {@link Status} element to test.
   * @return True if it's a successful element.
   */
  public static boolean isSuccessfulStatus(Status status) {
    return StatusCode.SUCCESS.equals(status.getStatusCode().getValue());
  }

  /**
   * Is the given status an authentication failure?
   *
   * @param status A {@link Status} element to test.
   * @return True if it's an authentication failure element.
   */
  public static boolean isAuthnFailureStatus(Status status) {
    StatusCode statusCode = status.getStatusCode();
    StatusCode secondaryCode = statusCode.getStatusCode();
    return (StatusCode.RESPONDER.equals(statusCode.getValue())
            && secondaryCode != null
            && StatusCode.AUTHN_FAILED.equals(secondaryCode.getValue()))
        // This next is for backwards compatibility; we used to generate this
        // (incorrect) status value.
        || StatusCode.AUTHN_FAILED.equals(statusCode.getValue());
  }

  /**
   * Is the given status a security failure?
   *
   * @param status A {@link Status} element to test.
   * @return True if it's a security failure element.
   */
  public static boolean isSecurityFailureStatus(Status status) {
    StatusCode statusCode = status.getStatusCode();
    StatusCode secondaryCode = statusCode.getStatusCode();
    return StatusCode.REQUESTER.equals(statusCode.getValue())
        && secondaryCode != null
        && StatusCode.REQUEST_DENIED.equals(secondaryCode.getValue());
  }

  /**
   * Static factory for SAML {@link StatusCode} objects.
   *
   * @param value A URI specifying one of the standard SAML status codes.
   * @return A new {@link StatusCode} object.
   */
  @Nonnull
  public static StatusCode makeStatusCode(String value) {
    Preconditions.checkArgument(validTopLevelStatusCodeUri(value));
    return makeStatusCodeInternal(value);
  }

  private static boolean validTopLevelStatusCodeUri(String value) {
    return StatusCode.SUCCESS.equals(value)
        || StatusCode.REQUESTER.equals(value)
        || StatusCode.RESPONDER.equals(value)
        || StatusCode.VERSION_MISMATCH.equals(value);
  }

  private static StatusCode makeStatusCodeInternal(String value) {
    StatusCode code = statusCodeBuilder.buildObject();
    code.setValue(value);
    return code;
  }

  /**
   * Static factory for SAML {@link StatusCode} objects.
   *
   * @param value A URI specifying one of the standard SAML status codes.
   * @param secondaryValue A URI specifying a secondary SAML status code.
   * @return A new {@link StatusCode} object.
   */
  @Nonnull
  public static StatusCode makeStatusCode(String value, String secondaryValue) {
    Preconditions.checkArgument(!Strings.isNullOrEmpty(secondaryValue));
    StatusCode code = makeStatusCode(value);
    code.setStatusCode(makeStatusCodeInternal(secondaryValue));
    return code;
  }

  /**
   * Static factory for SAML {@link StatusMessage} objects.
   *
   * @param value A status message string.
   * @return A new {@link StatusMessage} object.
   */
  @Nonnull
  public static StatusMessage makeStatusMessage(String value) {
    Preconditions.checkNotNull(value);
    StatusMessage message = statusMessageBuilder.buildObject();
    message.setMessage(value);
    return message;
  }

  /**
   * Static factory for SAML {@link Subject} objects.
   *
   * @param name The name identifying the subject.
   * @param confirmations The confirmations for this subject.
   * @return A new <code>Subject</code> object.
   */
  public static Subject makeSubject(String name, SubjectConfirmation... confirmations) {
    Subject samlSubject = subjectBuilder.buildObject();
    samlSubject.setNameID(makeNameId(name));
    if (confirmations != null) {
      samlSubject.getSubjectConfirmations().addAll(Arrays.asList(confirmations));
    }
    return samlSubject;
  }

  /**
   * Static factory for SAML {@link SubjectConfirmation} objects.
   *
   * @param method The method used to confirm the subject.
   * @param data The data about the confirmation.
   * @return A new <code>SubjectConfirmation</code> object.
   */
  public static SubjectConfirmation makeSubjectConfirmation(String method,
      SubjectConfirmationData data) {
    SubjectConfirmation confirmation = subjectConfirmationBuilder.buildObject();
    confirmation.setMethod(method);
    confirmation.setSubjectConfirmationData(data);
    return confirmation;
  }

  /**
   * Static factory for SAML {@link SubjectConfirmationData} objects.
   *
   * @param recipient The entity ID of the intended recipient.
   * @param expirationTime The expiration time for this subject.
   * @param inResponseTo The message ID of the AuthnRequest this is a response to.
   * @return A new <code>SubjectConfirmationData</code> object.
   */
  public static SubjectConfirmationData makeSubjectConfirmationData(String recipient,
      DateTime expirationTime, String inResponseTo) {
    SubjectConfirmationData data = subjectConfirmationDataBuilder.buildObject();
    data.setRecipient(recipient);
    data.setNotOnOrAfter(expirationTime);
    data.setInResponseTo(inResponseTo);
    return data;
  }

  /*
   * Metadata descriptions.
   */

  /**
   * Static factory for SAML {@link SingleSignOnService} objects.
   *
   * @param binding The SAML binding implemented by this service.
   * @param location The URL that the service listens to.
   * @return A new <code>SingleSignOnService</code> object.
   */
  public static SingleSignOnService makeSingleSignOnService(String binding, String location) {
    SingleSignOnService service = singleSignOnServiceBuilder.buildObject();
    service.setBinding(binding);
    service.setLocation(location);
    return service;
  }

  /*
   * Identifiers
   */

  /**
   * Generate a random identifier.
   *
   * @return A new identifier string.
   */
  public static String generateIdentifier() {
    return idGenerator.generateIdentifier();
  }

  /*
   * Context and codecs
   */

  /**
   * Static factory for OpenSAML message-context objects.
   *
   * @return A new message-context object.
   */
  public static <T extends SAMLObject> MessageContext<T> makeSamlMessageContext() {
    MessageContext<T> context = new org.opensaml.messaging.context.MessageContext<>();
    context.setAutoCreateSubcontexts(true);
    SAMLProtocolContext protocolContext = context.getSubcontext(SAMLProtocolContext.class);
    protocolContext.setProtocol(SAMLConstants.SAML20P_NS); // we only use SAML 2.0
    return context;
  }

  /**
   * Runs a message encoder.
   *
   * @param encoder The message encoder to run.
   * @param context The message context to pass to the encoder.
   * @param decorator A log-message decorator.
   * @throws IOException if unable to encode message.
   */
  public static void runEncoder(
      MessageEncoder<SAMLObject> encoder, MessageContext<SAMLObject> context, Decorator decorator)
      throws IOException {
    try {
      MessageHandler<SAMLObject> handler = getOutboundMessageHandlers(encoder);
      handler.initialize();
      handler.invoke(context);

      if (!encoder.isInitialized()) {
        encoder.setMessageContext(context);
        encoder.initialize();
      }
      encoder.prepareContext();
      encoder.encode();
    } catch (MessageEncodingException
        | ComponentInitializationException
        | MessageHandlerException e) {
      throw logCodecMessage(e, "encode", decorator, context);
    }
  }

  @SuppressWarnings("unchecked")
  private static MessageHandler<SAMLObject> getOutboundMessageHandlers(
      MessageEncoder<SAMLObject> encoder) {
    BasicMessageHandlerChain<SAMLObject> handler = new BasicMessageHandlerChain<>();
    List<MessageHandler<SAMLObject>> handlers = new ArrayList<>();
    SAMLOutboundDestinationHandler outboundDestinationHandler =
        new SAMLOutboundDestinationHandler();
    // This was implemented in HTTPPostEncoder and HTTPRedirectDeflateEncoder in OpenSaml v2
    outboundDestinationHandler.setActivationCondition(
        context ->
            encoder instanceof HTTPPostEncoder || encoder instanceof HTTPRedirectDeflateEncoder);
    handlers.add(outboundDestinationHandler);
    handlers.add(new SAMLOutboundProtocolMessageSigningHandler());

    handler.setHandlers(handlers);
    return handler;
  }

  /**
   * Runs a message decoder.
   *
   * @param decoder The message decoder to run.
   * @param decorator A log-message decorator.
   * @throws IOException if unable to decode message.
   */
  public static void runDecoder(
      MessageDecoder<SAMLObject> decoder, MessageContext<SAMLObject> context, Decorator decorator)
      throws IOException {
    try {
      if (!decoder.isInitialized()) {
        decoder.initialize();
      }
      decoder.decode();
    } catch (MessageDecodingException | ComponentInitializationException e) {
      throw logCodecMessage(e, "decode", decorator, decoder.getMessageContext());
    }
    mergeContexts(context, decoder.getMessageContext());
  }

  private static void mergeContexts(
      MessageContext<SAMLObject> context, MessageContext<SAMLObject> decodedContext) {
    context.setMessage(decodedContext.getMessage());
    for (BaseContext subContext : Lists.newArrayList(decodedContext)) {
      context.addSubcontext(subContext, true);
    }
  }

  /**
   * Runs the previously stored ({@link InboundMessageHandlerContext}) message handlers on message
   * context.
   *
   * @param context The message context to run the handlers on. Should contain {@link
   *     InboundMessageHandlerContext} as a sub-context.
   * @throws MessageHandlerException if the message handler throws an exception.
   */
  public static void runInboundMessageHandlers(MessageContext<SAMLObject> context)
      throws MessageHandlerException {
    MessageHandler<SAMLObject> handler =
        context.getSubcontext(InboundMessageHandlerContext.class, true).getMessageHandler();
    if (handler != null) {
      try {
        if (!handler.isInitialized()) {
          handler.initialize();
        }
        handler.invoke(context);
      } catch (ComponentInitializationException | MessageHandlerException e) {
        throw new MessageHandlerException(e);
      }
    }
  }

  /*
   * Starting from xmltooling 1.4.1, by default,
   * "http://apache.org/xml/features/disallow-doctype-decl" is set to true. And
   * it's not set (which means false implicitly) before. So, the result is GSA
   * of version 7.2 or before allows DOCTYPE in received SAML message. We want
   * the backward compatibility, so we need to explicitly allow DOCTYPE here.
   *
   * gsa-admin-toolkit/authn.py will continue working with this backward
   * compatible basic parser pool.
   */
  public static BasicParserPool getBasicParserPool() {
    return getBasicParserPoolInternal(ACCEPT_DTD);
  }

  @VisibleForTesting
  static BasicParserPool getBasicParserPoolInternal(boolean acceptDTD) {
    BasicParserPool parserPool = new BasicParserPool();
    Map<String, Boolean> newBuilderFeatures = new HashMap<String, Boolean>(
        parserPool.getBuilderFeatures());
    if (acceptDTD) {
      newBuilderFeatures.put("http://apache.org/xml/features/disallow-doctype-decl", false);
    }
    parserPool.setBuilderFeatures(newBuilderFeatures);
    try {
      parserPool.initialize();
    } catch (ComponentInitializationException e) {
      logger.warning("Failed to initialize parser pool: " + e.getMessage());
      throw new IllegalStateException("Failed to initialize parser pool", e);
    }
    return parserPool;
  }

  private static IOException logCodecMessage(
      Throwable e, String verbPhrase, Decorator decorator, MessageContext<SAMLObject> context) {
    String elementName =
        (context == null || context.getMessage() == null)
            ? ""
            : context.getMessage().getElementQName().getLocalPart();
    String message = "Unable to " + verbPhrase + " " + elementName + " message: ";
    logger.warning(decorator.apply(message + e.getMessage()));
    return new IOException(message, e);
  }

  /**
   * Get a SAML metadata resolver that reads from our template metadata file.
   *
   * @param file The file containing the metadata.
   * @return A metadata provider for the given file.
   * @throws ResolverException if there are problems reading the file.
   * @throws ComponentInitializationException if resolver cannot be initialized
   */
  public static FilesystemMetadataResolver getMetadataFromFile(
      File file, String urlPrefix, String configuredEntityId)
      throws ResolverException, ComponentInitializationException {
    FilesystemMetadataResolver resolver =
        new GsaFilesystemMetadataResolver(file, urlPrefix, configuredEntityId);
    resolver.setParserPool(OpenSamlUtil.getBasicParserPool());
    // Causes null-pointer errors in OpenSAML code:
    resolver.setRequireValidMetadata(true);
    resolver.setId(file.getAbsolutePath());
    resolver.setResolveViaPredicatesOnly(true);
    resolver.initialize();
    return resolver;
  }

  /**
   * Initializes the security policy for an inbound message. This validates the message signature
   * according to the policy.
   *
   * @param context The message context being used to decode the message.
   * @param handlers The message handlers to use.
   */
  @SafeVarargs
  public static void initializeSecurityPolicy(
      MessageContext<SAMLObject> context, MessageHandler<SAMLObject>... handlers) {
    MetadataResolver metadataResolver = null;
    SAMLPeerEntityContext peerEntityContext =
        context.getSubcontext(SAMLPeerEntityContext.class, true);
    Metadata.MetadataContext metadataContext =
        context.getSubcontext(Metadata.MetadataContext.class, false);
    if (peerEntityContext.getRole() != null && metadataContext != null) {
      metadataResolver = metadataContext.getMetadata().getResolver();
    } else {
      logger.warning("No peer entity role available, not using metadata credentials.");
    }
    KeyStore cacertsTrustStore;
    try {
      cacertsTrustStore = ConfigSingleton.getCacertsTrustStore();
    } catch (IOException e) {
      logger.warning("No CA certificates available, not using them: " + e.getMessage());
      cacertsTrustStore = null;
    } catch (GeneralSecurityException e) {
      logger.warning("No CA certificates available, not using them: " + e.getMessage());
      cacertsTrustStore = null;
    }
    initializeSecurityParametersContext(context, metadataResolver, cacertsTrustStore);
    addMessageHandlers(context, handlers);
  }

  private static void initializeSecurityParametersContext(
      MessageContext<SAMLObject> context,
      MetadataResolver metadataResolver,
      KeyStore cacertsTrustStore) {
    SecurityParametersContext secParams =
        context.getSubcontext(SecurityParametersContext.class, true);
    SignatureValidationParameters signatureValidationParameters =
        new SignatureValidationParameters();
    try {
      signatureValidationParameters.setSignatureTrustEngine(
          getStandardSignatureTrustEngine(metadataResolver, cacertsTrustStore));
    } catch (IOException e) {
      logger.warning("Failed to initialize signature validation parameters.");
    }
    secParams.setSignatureValidationParameters(signatureValidationParameters);
  }

  /** Entry point that allows the parameters to be injected. */
  @SafeVarargs
  @VisibleForTesting
  public static void addMessageHandlers(
      MessageContext<SAMLObject> context, MessageHandler<SAMLObject>... handlers) {
    SAMLPeerEntityContext peerEntityContext =
        context.getSubcontext(SAMLPeerEntityContext.class, true);
    if (peerEntityContext.getRole() == null) {
      // SAMLProtocolMessageXMLSignatureSecurityPolicyRule always generates a
      // MetadataCriteria, even if no metadata is to be used.  In turn,
      // MetadataCriteria requires peerEntityRole to be non-null, so we'd better
      // set it to something.  This value should be harmless.
      peerEntityContext.setRole(RoleDescriptor.DEFAULT_ELEMENT_NAME);
    }
    BasicMessageHandlerChain<SAMLObject> handlerChain = new BasicMessageHandlerChain<>();
    handlerChain.setHandlers(Arrays.asList(handlers));
    context.getSubcontext(InboundMessageHandlerContext.class, true).setMessageHandler(handlerChain);
  }

  private static SignatureTrustEngine getStandardSignatureTrustEngine(
      MetadataResolver metadataResolver, KeyStore cacertsTrustStore) throws IOException {
    KeyInfoCredentialResolver keyInfoCredentialResolver = getStandardKeyInfoCredentialResolver();
    List<CredentialResolver> resolvers = Lists.newArrayList();
    if (metadataResolver != null) {
      resolvers.add(metadataCredentialResolver(metadataResolver, keyInfoCredentialResolver));
    }
    if (cacertsTrustStore != null) {
      resolvers.add(CacertsCredentialResolver.make(cacertsTrustStore));
    }
    return new ExplicitKeySignatureTrustEngine(
        chainCredentialResolvers(resolvers), keyInfoCredentialResolver);
  }

  /** Gets a security policy rule that requires a message to have an Issuer. */
  @Nonnull
  @SuppressWarnings("unchecked")
  public static MessageHandler<SAMLObject> getCheckMandatoryIssuerHandler() {
    CheckMandatoryIssuer handler = new CheckMandatoryIssuer();
    handler.setIssuerLookupStrategy(context -> getMessageIssuer(context).getValue());
    return handler;
  }
  
  /** Resolves the {@link Issuer} of a message context
   *  
   *  @param context The message context
   */
  public static Issuer getMessageIssuer(MessageContext<SAMLObject> context) {
    Object msg = context.getMessage();
    if (msg instanceof AuthnRequest) {
      return ((AuthnRequest) msg).getIssuer();
    } else if (msg instanceof Response) {
      return ((Response) msg).getIssuer();
    } else if (msg instanceof AuthzDecisionQuery) {
      return ((AuthzDecisionQuery) msg).getIssuer();
    } else if (msg instanceof ArtifactResolve) {
      return ((ArtifactResolve) msg).getIssuer();
    } else if (msg instanceof ArtifactResponse) {
      return ((ArtifactResponse) msg).getIssuer();
    }
    throw new UnsupportedOperationException(
        "Unsupported message type: " + msg.getClass().getName());
  }

  /** Resolves the message ID of a message context
   *  
   *  @param context The message context
   */
  public static String getMessageId(MessageContext<SAMLObject> context) {
    Object msg = context.getMessage();
    if (msg instanceof AuthnRequest) {
      return ((AuthnRequest) context.getMessage()).getID();
    } else if (msg instanceof Response) {
      return ((Response) context.getMessage()).getID();
    }
    throw new IllegalArgumentException(
        "Unsupported message type: " + context.getMessage().getElementQName());
  }

  /** Gets a security policy rule that requires a message to have a valid signature. */
  @Nonnull
  @SuppressWarnings("unchecked")
  public static MessageHandler<SAMLObject> getCheckMandatoryAuthenticatedMessageHandler() {
    CheckMandatoryAuthentication handler = new CheckMandatoryAuthentication();
    handler.setAuthenticationLookupStrategy(
        c -> c.getSubcontext(SAMLPeerEntityContext.class, true).isAuthenticated());
    return handler;
  }

  /**
   * Gets a security policy rule that requires a signature to be present if the metadata says it's
   * supposed to be there.
   */
  @Nonnull
  public static MessageHandler<SAMLObject> getAuthnRequestsSignedHandler() {
    return new SAML2AuthnRequestsSignedSecurityHandler();
  }

  /** Gets a security policy rule for XML signatures, using metadata credentials. */
  @Nonnull
  @SuppressWarnings("unchecked")
  public static MessageHandler<SAMLObject> getXmlSignatureHandler() {
    return new SAMLProtocolMessageXMLSignatureSecurityHandler();
  }

  /** Gets a security policy handler for the redirect binding, using metadata credentials. */
  @Nonnull
  @SuppressWarnings("unchecked")
  public static MessageHandler<SAMLObject> getRedirectSignatureHandler(HttpServletRequest request) {
    SAML2HTTPRedirectDeflateSignatureSecurityHandler handler =
        new SAML2HTTPRedirectDeflateSignatureSecurityHandler();
    handler.setHttpServletRequest(request);
    return handler;
  }

  private static CredentialResolver metadataCredentialResolver(
      MetadataResolver metadataResolver, KeyInfoCredentialResolver keyInfoCredentialResolver) {
    MetadataCredentialResolver credentialResolver = new MetadataCredentialResolver();
    PredicateRoleDescriptorResolver roleDescriptorResolver =
        new PredicateRoleDescriptorResolver(metadataResolver);
    credentialResolver.setRoleDescriptorResolver(roleDescriptorResolver);
    credentialResolver.setKeyInfoCredentialResolver(keyInfoCredentialResolver);
    try {
      credentialResolver.initialize();
      roleDescriptorResolver.initialize();
    } catch (ComponentInitializationException e) {
      logger.warning("Failed to initialize metadata credential resolver: " + e.getMessage());
      throw new IllegalStateException("Failed to initialize metadata credential resolver", e);
    }
    return credentialResolver;
  }

  private static CredentialResolver chainCredentialResolvers(List<CredentialResolver> resolvers)
      throws IOException {
    switch (resolvers.size()) {
      case 0:
        throw new IOException();
      case 1:
        return resolvers.get(0);
      default:
        ChainingCredentialResolver chainingCredentialResolver =
            new ChainingCredentialResolver(resolvers);
        return chainingCredentialResolver;
    }
  }

  /**
   * Make a KeyInfoCredentialResolver that knows about some basic credential types.
   *
   * @return A new KeyInfoCredentialResolver.
   */
  public static synchronized KeyInfoCredentialResolver getStandardKeyInfoCredentialResolver() {
    if (standardKeyInfoCredentialResolver == null) {
      List<KeyInfoProvider> providers = Lists.newArrayList();
      providers.add(new DSAKeyValueProvider());
      providers.add(new RSAKeyValueProvider());
      providers.add(new InlineX509DataProvider());
      standardKeyInfoCredentialResolver = new BasicProviderKeyInfoCredentialResolver(providers);
    }
    return standardKeyInfoCredentialResolver;
  }

  private static KeyInfoCredentialResolver standardKeyInfoCredentialResolver = null;

  /**
   * Return the standard credentials from a given KeyInfo object.
   *
   * @param keyInfo The KeyInfo object to examine.
   * @return The standard credentials found in the object.
   * @throws ResolverException
   */
  public static Iterable<Credential> resolveStandardKeyInfoCredentials(KeyInfo keyInfo)
      throws ResolverException {
    return getStandardKeyInfoCredentialResolver()
        .resolve(new CriteriaSet(new KeyInfoCriterion(keyInfo)));
  }

  /**
   * Read a PEM-encoded X.509 certificate file and its associated private-key file and
   * return an {@link X509Credential} object.
   *
   * @param certFile The certificate file.
   * @param keyFile The private-key file.
   * @return The credential object, never null.
   * @throws IOException if there's some kind of error reading or converting the files.
   */
  public static Credential readX509Credential(File certFile, File keyFile)
      throws IOException {
    return CredentialSupport.getSimpleCredential(
        readX509CertificateFile(certFile), readPrivateKeyFile(keyFile));
  }

  /**
   * Read a PEM-encoded X.509 certificate file and return it as an {@link X509Certificate}
   * object.
   *
   * @param file The file to read.
   * @return The certificate object, never null.
   * @throws IOException if there's some kind of error reading or converting the file.
   */
  public static X509Certificate readX509CertificateFile(File file)
      throws IOException {
    String base64Cert = FileUtil.readPEMCertificateFile(file);
    try {
      return X509Support.decodeCertificate(base64Cert);
    } catch (CertificateException e) {
      throw new IOException(e);
    }
  }

  /**
   * Read a PEM-encoded private-key file and return it as a {@link PrivateKey} object.
   *
   * @param file The file to read.
   * @return The private-key object, never null.
   * @throws IOException if there's some kind of error reading or converting the file.
   */
  public static PrivateKey readPrivateKeyFile(File file)
      throws IOException {
    try {
      return KeySupport.decodePrivateKey(file, new char[0]);
    } catch (KeyException e) {
      throw new IOException(e);
    }
  }

  /**
   * Gets a child of a given SAML object that has a given type.
   *
   * @param object A SAML object to get the child from.
   * @param type A type for the child to get.
   * @return A child of that type, or {@code null} if there isn't one.
   */
  public static <T extends XMLObject> T getChild(SAMLObject object, Class<T> type) {
    for (XMLObject child : object.getOrderedChildren()) {
      if (type.isInstance(child)) {
        return type.cast(child);
      }
    }
    return null;
  }

  /**
   * Convert an OpenSAML object to a DOM object.
   *
   * @param xmlObject The OpenSAML object to convert.
   * @return The corresponding DOM object.
   * @throws MarshallingException if unable to convert object.
   */
  public static Element marshallXmlObject(XMLObject xmlObject) throws MarshallingException {
    return XMLObjectProviderRegistrySupport.getMarshallerFactory()
        .getMarshaller(xmlObject)
        .marshall(xmlObject);
  }

  /**
   * Convert a DOM object to an OpenSAML object.
   *
   * @param element A DOM object representing a SAML element.
   * @return The corresponding OpenSAML object.
   * @throws UnmarshallingException if unable to convert object.
   */
  public static XMLObject unmarshallXmlObject(Element element) throws UnmarshallingException {
    return XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
        .getUnmarshaller(element)
        .unmarshall(element);
  }

  /**
   * Makes a new artifact map.
   *
   * @param artifactLifetime The lifetime of the map's artifacts, in milliseconds.
   * @return A new artifact map.
   */
  @Nonnull
  public static SAMLArtifactMap makeArtifactMap(@Nonnegative long artifactLifetime) {
    Preconditions.checkArgument(artifactLifetime >= 0);
    BasicSAMLArtifactMap artifactMap = new BasicSAMLArtifactMap();
    artifactMap.setArtifactLifetime(artifactLifetime);
    try {
      artifactMap.initialize();
    } catch (ComponentInitializationException e) {
      logger.severe("Failed to initialize artifact map: " + e.getMessage());
      throw new RuntimeException(e);
    }
    return artifactMap;
  }

  /**
   * Sets signature signing parameters on a message context
   *
   * @param context The {@link MessageContext} to set signing parameters on.
   * @param credential The {@link Credential} to use for signing.
   */
  public static void initializeSigningParameters(
      MessageContext<? extends SAMLObject> context, Credential credential) {
    if (credential != null) {
      SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
      signatureSigningParameters.setSigningCredential(credential);
      // TODO: Using SHA1 for maximum backward compatibility, SHA256 is preferred
      signatureSigningParameters.setSignatureAlgorithm(
          SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
      signatureSigningParameters.setSignatureReferenceDigestMethod(
          SignatureConstants.ALGO_ID_DIGEST_SHA1);
      signatureSigningParameters.setSignatureCanonicalizationAlgorithm(
          SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

      X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
      keyInfoGeneratorFactory.setEmitEntityCertificate(true);
      signatureSigningParameters.setKeyInfoGenerator(keyInfoGeneratorFactory.newInstance());
      context
          .getSubcontext(SecurityParametersContext.class, true)
          .setSignatureSigningParameters(signatureSigningParameters);
    }
  }
}
