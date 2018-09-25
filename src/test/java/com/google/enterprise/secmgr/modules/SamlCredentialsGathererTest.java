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

package com.google.enterprise.secmgr.modules;

import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAuthnFailureStatus;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logOk;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logPost;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logRedirect;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logResponse;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logSequence;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static javax.servlet.http.HttpServletResponse.SC_OK;

import com.google.common.base.Function;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.ExportedState;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.AuthnMechGroups;
import com.google.enterprise.secmgr.config.AuthnMechSaml;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.http.HttpExchange;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.GroupMemberships;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.mock.MockHttpTransport.ResponseAction;
import com.google.enterprise.secmgr.mock.MockIntegration;
import com.google.enterprise.secmgr.mock.MockSamlIdp;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.servlets.FailureResponseGenerator;
import com.google.enterprise.secmgr.servlets.ResponseGenerator;
import com.google.enterprise.secmgr.servlets.SamlArtifactResolve;
import com.google.enterprise.secmgr.servlets.SamlAssertionConsumer;
import com.google.enterprise.secmgr.servlets.SimpleResponseGenerator;
import com.google.enterprise.secmgr.testing.ExchangeLog.LogItem;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;

/**
 * Tests of the SAML client.
 */
public class SamlCredentialsGathererTest extends SecurityManagerTestCase {

  private static final String SAML_IDP1_CONTEXT_URL = "http://saml.example.com";
  private static final String SAML_IDP1_ENTITY_ID = "http://example.com/saml-idp-1";

  private static final String SAML_IDP2_CONTEXT_URL = "http://saml.foobar.org";
  private static final String SAML_IDP2_ENTITY_ID = "http://foobar.org/saml-idp-2";
  private static final String SAML_IDP2_PARAM_1 = "OpenForm";

  private static final String SAML_IDP3_CONTEXT_URL = "http://saml.foobaz.org";
  private static final String SAML_IDP3_ENTITY_ID = "http://foobaz.org/saml-idp-3";

  private static final String SAML_IDP4_CONTEXT_URL = "http://saml.mumble.com";
  private static final String SAML_IDP4_ENTITY_ID = "http://mumble.com/saml-idp-4";

  private static final String SAML_IDP5_CONTEXT_URL = "http://saml.frotz.com";
  private static final String SAML_IDP5_ENTITY_ID = "http://frotz.com/saml-idp-5";

  private static final String SAML_IDP6_CONTEXT_URL = "http://saml.frotz.net";
  private static final String SAML_IDP6_ENTITY_ID = "http://frotz.net/saml-idp-6";

  private static final String SAML_IDP7_CONTEXT_URL = "http://saml.example.com";
  private static final String SAML_IDP7_ENTITY_ID = "http://example.com/saml-idp-7";

  private static final long TEST_TRUST_DURATION = 12345678;

  private final MockIntegration integration;
  private final MockSamlIdp mockSamlIdp1;
  private final MockSamlIdp mockSamlIdp2;
  private final ImmutableList<MockSamlIdp> mockSamlIdps;

  public SamlCredentialsGathererTest()
      throws IOException, ServletException {
    integration = MockIntegration.make();

    // We always sign with the same credential, independent of the
    // configuration metadata.  This allows testing what happens when the
    // configured credential doesn't match the actual credential.
    Supplier<org.opensaml.xml.security.credential.Credential> signingCredentialSupplier
        = Suppliers.<org.opensaml.xml.security.credential.Credential>ofInstance(
            OpenSamlUtil.readX509Credential(
                FileUtil.getContextFile("saml-client-test.crt"),
                FileUtil.getContextFile("saml-client-test.key")));
    Metadata metadata = integration.getMetadata();

    // Make mock SAML auth servers.
    ImmutableList.Builder<MockSamlIdp> builder = ImmutableList.builder();
    mockSamlIdp1
        = makeSamlIdp(metadata, SAML_IDP1_ENTITY_ID, SAML_IDP1_CONTEXT_URL, "jack",
            SAMLConstants.SAML2_ARTIFACT_BINDING_URI, null, null);
    builder.add(mockSamlIdp1);
    mockSamlIdp2
        = makeSamlIdp(metadata, SAML_IDP2_ENTITY_ID, SAML_IDP2_CONTEXT_URL, "jill",
            SAMLConstants.SAML2_POST_BINDING_URI, signingCredentialSupplier, null);
    mockSamlIdp2.addRequiredQueryParameter(SAML_IDP2_PARAM_1);
    builder.add(mockSamlIdp2);
    builder.add(
        makeSamlIdp(metadata, SAML_IDP3_ENTITY_ID, SAML_IDP3_CONTEXT_URL, "hill",
            SAMLConstants.SAML2_POST_BINDING_URI, signingCredentialSupplier, null));
    builder.add(
        makeSamlIdp(metadata, SAML_IDP4_ENTITY_ID, SAML_IDP4_CONTEXT_URL, "bill",
            SAMLConstants.SAML2_POST_BINDING_URI, null, null));
    builder.add(
        makeSamlIdp(metadata, SAML_IDP5_ENTITY_ID, SAML_IDP5_CONTEXT_URL, "fill",
            SAMLConstants.SAML2_POST_BINDING_URI, signingCredentialSupplier, null));
    builder.add(
        makeSamlIdp(metadata, SAML_IDP6_ENTITY_ID, SAML_IDP6_CONTEXT_URL, "till",
            SAMLConstants.SAML2_POST_BINDING_URI, signingCredentialSupplier,
            integration.getSmEntityContextUrl() + "/assertionconsumer-not"));
    builder.add(
        makeSamlIdp(metadata, SAML_IDP7_ENTITY_ID, SAML_IDP7_CONTEXT_URL, "jack",
            SAMLConstants.SAML2_ARTIFACT_BINDING_URI, signingCredentialSupplier, null));
    mockSamlIdps = builder.build();

    for (MockSamlIdp idp : mockSamlIdps) {
      integration.addMockServer(idp);
    }
  }

  private static MockSamlIdp makeSamlIdp(Metadata metadata, String entityId, String contextUrl,
      String subjectName, String binding,
      Supplier<org.opensaml.xml.security.credential.Credential> signingCredentialSupplier,
      String destinationOverride) {
    return new MockSamlIdp(
        SamlSharedData.make(entityId, SamlSharedData.Role.IDENTITY_PROVIDER,
            signingCredentialSupplier),
        binding,
        metadata,
        contextUrl,
        destinationOverride,
        makeSuccessResponseSupplier(subjectName, null));
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    integration.reset();
    integration.getAuthnController().setMaxPrompts(1);
  }

  public void testSamlArtifact() {
    integration.setTestName();
    setupSaml(SAML_IDP1_ENTITY_ID);
    integration.assertStatusResult(SC_OK, 1, integration.startSearch());
    integration.checkExchangeLog(makeSamlArtifactLog());
  }

  public void testSamlArtifactSigned() {
    integration.setTestName();
    setupSaml(SAML_IDP7_ENTITY_ID);
    integration.assertStatusResult(SC_OK, 1, integration.startSearch());
    integration.checkExchangeLog(makeSamlArtifactLog());
  }

  public void testSamlArtifactMultiId() {
    integration.setTestName();
    List<CredentialGroup> credentialGroups = setupSaml(SAML_IDP1_ENTITY_ID);
    mockSamlIdp1.setCredentialGroups(credentialGroups);
    String cgName = credentialGroups.get(0).getName();    
    AuthnAuthority authority1 = credentialGroups.get(0).getMechanisms().get(0).getAuthority();
    AuthnAuthority authority2 = AuthnAuthority.make();
    Credential credential = AuthnPrincipal.make("jack", cgName);
    mockSamlIdp1.addVerification(authority1,
        Verification.verified(Verification.NEVER_EXPIRES, credential));
    mockSamlIdp1.addVerification(authority2,
        Verification.verified(Verification.NEVER_EXPIRES, credential));

    integration.assertStatusResult(SC_OK, 1, integration.startSearch());
    integration.checkExchangeLog(makeSamlArtifactLog());
    mockSamlIdp1.setCredentialGroups(null);
    ExportedState state
        = (ExportedState) integration.getUserAgent().getSession().getAttribute("exportedState");
    AuthnSessionState.Summary summary1
        = integration.getSession().getSnapshot().getState().computeSummary(credentialGroups);
    AuthnSessionState.Summary summary2 = state.getSessionState().computeSummary(credentialGroups);
    Predicate<AuthnAuthority> p1 = Predicates.equalTo(authority1);
    Predicate<AuthnAuthority> p2 = Predicates.equalTo(authority2);
    long now = DateTimeUtils.currentTimeMillis();
    assertEquals(summary1.getVerifications(p1, now), summary1.getVerifications(p1, now));
    assertEquals(summary2.getVerifications(p2, now), summary2.getVerifications(p2, now));
  }

  public void testSamlArtifactGroups() {
    integration.setTestName();
    List<CredentialGroup> credentialGroups = setupSaml(SAML_IDP1_ENTITY_ID);
    mockSamlIdp1.setCredentialGroups(credentialGroups);
    CredentialGroup cg = credentialGroups.get(0);
    AuthnMechanism mechanism = cg.getMechanisms().get(0);
    Set<Credential> credentials
        = ImmutableSet.<Credential>of(
            AuthnPrincipal.make("jack", cg.getName()),
            GroupMemberships.make(ImmutableSet.of(
            Group.make("groupA", cg.getName()), Group.make("groupB", cg.getName()))));
    mockSamlIdp1.addVerification(mechanism.getAuthority(),
        Verification.verified(Verification.NEVER_EXPIRES, credentials));

    integration.assertStatusResult(SC_OK, 1, integration.startSearch());
    integration.checkExchangeLog(makeSamlArtifactLog());

    Set<Verification> verifications
        = ImmutableSet.copyOf(integration.getSession().getView(mechanism).getVerifications());
    assertEquals(2, verifications.size());
    Iterator<Verification> it = verifications.iterator();
    while (it.hasNext()) {
      Verification verification = it.next();
      if (verification.getCredentials().size() > 0) {
        assertTrue(verification.isVerified());
        assertEquals(credentials, verification.getCredentials());
      }
    }    
  }

  /**
   * Tests behavior of SamlAssertionConsumer#doGet when no session cookie is sent.
   */
  public void testSamlAssertionConsumerGetMissingSessionCookie() {
    integration.setTestName();
    setupSaml(SAML_IDP1_ENTITY_ID);
    integration.getHttpTransport().registerResponseAction(MockSamlIdp.class,
        new ResponseAction() {
          @Override
          public void apply(HttpServletResponse response) {
            integration.deleteUserAgentCookie(SessionUtil.GSA_SESSION_ID_COOKIE_NAME);
          }
        });
    integration.assertStatusResult(SC_INTERNAL_SERVER_ERROR, integration.startSearch());
    integration.checkExchangeLog(
        logSequence(
            MockIntegration.standardLogPrefix(),
            logRedirect(MockSamlIdp.class.getSimpleName()),
            logRedirect(SamlAssertionConsumer.class.getSimpleName()),
            logResponse(SC_INTERNAL_SERVER_ERROR)));
  }

  private static LogItem makeSamlArtifactLog() {
    return logSequence(
        MockIntegration.standardLogPrefix(),
        // SecMgr redirects to external SAML server.
        logRedirect(MockSamlIdp.class.getSimpleName()),
        // Which, in real life, might redirect to a form; but here it just
        // creates an artifact and redirects to the SecMgr's SAML assertion
        // consumer.
        logRedirect(SamlAssertionConsumer.class.getSimpleName(),
            // The assertion consumer resolves the artifact.
            logPost(SamlArtifactResolve.class.getSimpleName()),
            logOk()),
        MockIntegration.successfulLogSuffix());
  }

  public void testSamlPostOk() {
    integration.setTestName();
    setupSaml(SAML_IDP2_ENTITY_ID);
    integration.assertStatusResult(SC_OK, 1, trySamlPost());
    integration.checkExchangeLog(makeSamlPostOkLog());
  }

  public void testSamlPostFail() {
    integration.setTestName();
    setupSaml(SAML_IDP2_ENTITY_ID);
    mockSamlIdp2.setResponseGeneratorSupplier(makeFailureResponseSupplier());
    integration.assertFailureResult(trySamlPost());
    integration.checkExchangeLog(makeSamlPostFailLog());
  }

  public void testSamlPostWrongCert() {
    integration.setTestName();
    setupSaml(SAML_IDP3_ENTITY_ID);
    integration.assertFailureResult(trySamlPost());
    integration.checkExchangeLog(makeSamlPostErrorLog());
  }

  public void testSamlPostNoSignature() {
    integration.setTestName();
    setupSaml(SAML_IDP4_ENTITY_ID);
    integration.assertFailureResult(trySamlPost());
    integration.checkExchangeLog(makeSamlPostErrorLog());
  }

  public void testSamlPostNoCert() {
    integration.setTestName();
    setupSaml(SAML_IDP5_ENTITY_ID);
    integration.assertFailureResult(trySamlPost());
    integration.checkExchangeLog(makeSamlPostErrorLog());
  }

  public void testSamlPostWrongRecipient() {
    integration.setTestName();
    setupSaml(SAML_IDP6_ENTITY_ID);
    integration.assertFailureResult(trySamlPost());
    integration.checkExchangeLog(makeSamlPostErrorLog());
  }

  public void testSamlRetryOnRefute() {
    integration.setTestName();
    setupSaml(SAML_IDP2_ENTITY_ID);
    mockSamlIdp2.setResponseGeneratorSupplier(makeFailureResponseSupplier());
    integration.assertFailureResult(trySamlPost());
    integration.checkExchangeLog(makeSamlPostFailLog());

    mockSamlIdp2.reset();

    integration.assertStatusResult(SC_OK, 1, trySamlPost());
    integration.checkExchangeLog(makeSamlPostOkLog());
  }

  /**
   * Tests behavior of SamlAssertionConsumer#doPost when no session cookie is sent.
   */
  public void testSamlAssertionConsumerPostMissingSessionCookie() {
    integration.setTestName();
    setupSaml(SAML_IDP2_ENTITY_ID);
    integration.getHttpTransport().registerResponseAction(MockSamlIdp.class,
        new ResponseAction() {
          @Override
          public void apply(HttpServletResponse response) {
            integration.deleteUserAgentCookie(SessionUtil.GSA_SESSION_ID_COOKIE_NAME);
          }
        });
    integration.assertStatusResult(SC_INTERNAL_SERVER_ERROR, trySamlPost());
    integration.checkExchangeLog(
        logSequence(
            MockIntegration.standardLogPrefix(),
            makeSamlPostLogStep(),
            logResponse(SC_INTERNAL_SERVER_ERROR)));
  }


  public void testSamlAssertionGoodWithValidTrustDuration() {
    integration.setTestName();

    long someValidFutureTime = DateTimeUtils.currentTimeMillis() + 10000000;
    List<CredentialGroup> credentialGroups = setupSaml(SAML_IDP2_ENTITY_ID);
    mockSamlIdp2.setResponseGeneratorSupplier(
        makeSuccessResponseSupplier("fickle", new DateTime(someValidFutureTime)));
    integration.assertStatusResult(SC_OK, 1, trySamlPost());
    AuthnMechanism mechanism = credentialGroups.get(0).getMechanisms().get(0);
    Set<Verification> verifications
        = ImmutableSet.copyOf(integration.getSession().getView(mechanism).getVerifications());
    assertTrue(Verification.isVerified(verifications));
    Verification verification = verifications.iterator().next();
    assertNotNull(verification);

    // the expiration time for the verification should be somewhere
    //  between (now , now + TEST_TRUST_DURATION)
    long currentTime = DateTimeUtils.currentTimeMillis();
    assertTrue(verification.getExpirationTime() >=  currentTime);
    assertTrue(verification.getExpirationTime() <=  currentTime + TEST_TRUST_DURATION);
  }

  public void testSamlAssertionExpired5() {
    integration.setTestName();
    trySamlAssertionExpired(5000);
  }

  public void testSamlAssertionExpired10() {
    integration.setTestName();
    trySamlAssertionExpired(10000);
  }

  public void testSamlAssertionExpired20() {
    integration.setTestName();
    trySamlAssertionExpired(20000);
  }

  private void trySamlAssertionExpired(int duration) {
    List<CredentialGroup> credentialGroups = setupSaml(SAML_IDP2_ENTITY_ID);
    long expirationTime = DateTimeUtils.currentTimeMillis() + duration;
    DateTimeUtils.setCurrentMillisOffset(duration + SecurityManagerUtil.getClockSkewTime() + 1);
    mockSamlIdp2.setResponseGeneratorSupplier(
        makeSuccessResponseSupplier("fickle", new DateTime(expirationTime)));
    integration.assertFailureResult(trySamlPost());
    AuthnMechanism mechanism = credentialGroups.get(0).getMechanisms().get(0);
    Set<Verification> verifications
        = ImmutableSet.copyOf(integration.getSession().getView(mechanism).getVerifications());
    assertTrue(Verification.isIndeterminate(verifications));
  }

  private HttpExchange trySamlPost() {
    return continueSamlPost(integration.startSearch());
  }

  private HttpExchange continueSamlPost(HttpExchange exchange) {
    integration.assertStatusResult(SC_OK, exchange);
    return integration.processPostForm(exchange);
  }

  private static LogItem makeSamlPostOkLog() {
    return logSequence(
        MockIntegration.standardLogPrefix(),
        makeSamlPostLogStep(),
        MockIntegration.successfulLogSuffix());
  }

  private static LogItem makeSamlPostFailLog() {
    return logSequence(
        MockIntegration.standardLogPrefix(),
        makeSamlPostLogStep(),
        MockIntegration.unsuccessfulLogSuffix());
  }

  private static LogItem makeSamlPostErrorLog() {
    return logSequence(
        MockIntegration.standardLogPrefix(),
        makeSamlPostLogStep(),
        MockIntegration.unsuccessfulLogSuffix());
  }

  private static LogItem makeSamlPostLogStep() {
    return logSequence(
        // SecMgr redirects to external SAML server.
        logRedirect(MockSamlIdp.class.getSimpleName()),
        // Which, in real life, might redirect to a form; here it just replies
        // with a form that will auto-POST to the assertion consumer.
        logOk(),
        logPost(SamlAssertionConsumer.class.getSimpleName()));
  }

  private List<CredentialGroup> setupSaml(String entityId) {
    return setConfig(Lists.newArrayList(
        credGroupBuilder(0, true, false, false)
        .addMechanism(0, AuthnMechSaml.make("mech1", entityId,
            AuthnMechanism.NO_TIME_LIMIT, TEST_TRUST_DURATION))
        .addMechanism(1, AuthnMechGroups.make("mechGroup"))
        .build()));
  }

  private static CredentialGroup.Builder credGroupBuilder(int index, boolean requiresUsername,
      boolean requiresPassword, boolean isOptional) {
    String name = "group" + (index + 1);
    return CredentialGroup.builder(name, name + " display", requiresUsername, requiresPassword,
        isOptional);
  }

  private List<CredentialGroup> setConfig(List<CredentialGroup> credentialGroups) {
    SecurityManagerConfig config = makeConfig(credentialGroups);
    ConfigSingleton.setConfig(config);
    for (MockSamlIdp idp : mockSamlIdps) {
      idp.setConfig(config);
    }
    return credentialGroups;
  }

  private static Function<SAMLMessageContext<AuthnRequest, Response, NameID>, ResponseGenerator>
      makeSuccessResponseSupplier(final String subjectName, final DateTime expirationTime) {
    return new Function<SAMLMessageContext<AuthnRequest, Response, NameID>, ResponseGenerator>() {
      public ResponseGenerator apply(
          SAMLMessageContext<AuthnRequest, Response, NameID> context) {
        return new SuccessResponseGenerator(context, subjectName, expirationTime);
      }
    };
  }

  private static Function<SAMLMessageContext<AuthnRequest, Response, NameID>, ResponseGenerator>
      makeFailureResponseSupplier() {
    return new Function<SAMLMessageContext<AuthnRequest, Response, NameID>, ResponseGenerator>() {
      public ResponseGenerator apply(
          SAMLMessageContext<AuthnRequest, Response, NameID> context) {
        return new FailureResponseGenerator(context, makeAuthnFailureStatus());
      }
    };
  }

  private static final class SuccessResponseGenerator extends SimpleResponseGenerator {

    protected final String subjectName;
    protected final DateTime expirationTime;

    public SuccessResponseGenerator(SAMLMessageContext<AuthnRequest, Response, NameID> context,
        String subjectName, DateTime expirationTime) {
      super(context);
      this.subjectName = subjectName;
      this.expirationTime = expirationTime;
    }

    @Override
    protected String buildSubjectName(SessionSnapshot snapshot) {
      return subjectName;
    }

    @Override
    protected AttributeStatement buildAttributeStatement(SessionSnapshot snapshot) {
      return (snapshot != null) ? super.buildAttributeStatement(snapshot) : null;
    }

    @Override
    protected DateTime getExpirationTime(SessionSnapshot snapshot) {
      return (expirationTime != null) ? expirationTime : super.getExpirationTime(snapshot);
    }
  }
}
