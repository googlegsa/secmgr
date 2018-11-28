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

import static com.google.enterprise.secmgr.mock.MockIntegration.artifactLogSuffix;
import static com.google.enterprise.secmgr.mock.MockIntegration.postLogSuffix;
import static com.google.enterprise.secmgr.mock.MockIntegration.renderUlf;
import static com.google.enterprise.secmgr.mock.MockIntegration.sendBadCredsToAuthServer;
import static com.google.enterprise.secmgr.mock.MockIntegration.sendGoodCredsToAuthServer;
import static com.google.enterprise.secmgr.mock.MockIntegration.standardLogPrefix;
import static com.google.enterprise.secmgr.mock.MockIntegration.successfulLogSuffix;
import static com.google.enterprise.secmgr.mock.MockIntegration.successfulSampleUrlCheck;
import static com.google.enterprise.secmgr.mock.MockIntegration.ulfExchange;
import static com.google.enterprise.secmgr.mock.MockIntegration.unfinishedLogSuffix;
import static com.google.enterprise.secmgr.mock.MockIntegration.unsuccessfulLogSuffix;
import static com.google.enterprise.secmgr.mock.MockIntegration.unsuccessfulSampleUrlCheck;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logForbidden;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logGet;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logOk;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logPost;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logRedirect;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logResponse;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logSequence;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static javax.servlet.http.HttpServletResponse.SC_NOT_FOUND;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static javax.servlet.http.HttpServletResponse.SC_PARTIAL_CONTENT;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;

import com.google.common.base.Function;
import com.google.common.base.Strings;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSession.AuthnState;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.AuthnMechConnector;
import com.google.enterprise.secmgr.config.AuthnMechForm;
import com.google.enterprise.secmgr.config.AuthnMechGroups;
import com.google.enterprise.secmgr.config.AuthnMechKerberos;
import com.google.enterprise.secmgr.config.AuthnMechSampleUrl;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.AuthzMechanism;
import com.google.enterprise.secmgr.config.ConfigParams;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.ConnMgrInfo;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.FlexAuthorizer;
import com.google.enterprise.secmgr.config.FlexAuthzRoutingTableEntry;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.enterprise.secmgr.config.ParamName;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.http.ConnectorUtil;
import com.google.enterprise.secmgr.http.HttpExchange;
import com.google.enterprise.secmgr.http.SlowHostTracker;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.GroupMemberships;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.mock.MockAlternateServiceProvider;
import com.google.enterprise.secmgr.mock.MockCMAuthServer;
import com.google.enterprise.secmgr.mock.MockContentServer;
import com.google.enterprise.secmgr.mock.MockContentServer.COOKIE_VALUES;
import com.google.enterprise.secmgr.mock.MockFormAuthServer;
import com.google.enterprise.secmgr.mock.MockFormAuthServer.Form1;
import com.google.enterprise.secmgr.mock.MockGetConnectorInstanceList;
import com.google.enterprise.secmgr.mock.MockHttpClient;
import com.google.enterprise.secmgr.mock.MockIntegration;
import com.google.enterprise.secmgr.mock.MockRelyingParty;
import com.google.enterprise.secmgr.mock.MockServiceProvider;
import com.google.enterprise.secmgr.modules.AuthzCacheModule;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.modules.GroupsUpdateModule;
import com.google.enterprise.secmgr.modules.SamlAuthzClient;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.secmgr.testing.ExchangeLog.LogItem;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.enterprise.secmgr.testing.ServletTestUtil;
import com.google.enterprise.sessionmanager.MockSessionManagerBackend;
import com.google.enterprise.sessionmanager.SessionManagerBase;
import com.google.enterprise.util.C;
import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import org.joda.time.DateTimeUtils;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.xml.security.credential.Credential;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.w3c.dom.Element;

/**
 * An end-to-end test of the SAML SSO protocol.  This tests the security manager in an
 * environment that mocks both the GSA and the customer identity providers.
 *
 * TODO: This class has a tremendously useful infrastructure for testing,
 * but it's become too large, and contains many tests not directly related to
 * "SamlSso."  We should refactor out the useful infrastructure and break this
 * into a number of separate test files.
 *
 *  TODO: wrt the above- there is a file-level startup sequence that
 *  takes about 15 seconds.  When we break this into multiple files, we'll be
 *  multiplying that delay.  Is there anything we can do to make startup faster?
 */
public class SamlSsoTest extends SecurityManagerTestCase {
  private static final Logger logger = Logger.getLogger(SamlSsoTest.class.getName());

  private static final String ALT_GSA_HOST = "127.0.0.1";

  private static final String HOST_DOMAIN = ".foobar.org";
  private static final String GSA_IN_HOST_DOMAIN = "gsa" + HOST_DOMAIN;

  private static final String FORM2_CONTEXT_URL = "http://form2" + HOST_DOMAIN;
  private static final String FORM3_CONTEXT_URL = "http://form3" + HOST_DOMAIN;
  private static final String FORM4_CONTEXT_URL = "http://form4" + HOST_DOMAIN;
  private static final String FORM5_CONTEXT_URL = "http://form5" + HOST_DOMAIN;

  private static final String ALT_SP_ENTITY_ROOT = "http://example.com/alternate-service-provider-";

  private static final String BAD_USERNAME = "john";
  private static final String BAD_PASSWORD = "biden";
  private static final String BAD_PASSWORD2 = "funky";
  private static final String KERBEROS_USERNAME = "goodKerberos";
  private static final String KERBEROS_DOMAIN = "domain.company.com";
  private static final String KERBEROS_RESPONSE_GOOD =
      "Negotiate fake_spnego_header: " + KERBEROS_USERNAME + "@" + KERBEROS_DOMAIN + "";
  private static final String KERBEROS_RESPONSE_BAD = "Negotiate badKerberos";
  private static final String KERBEROS_RESPONSE_INVALID = "invalid Kerberos";

  private static final String CM1_NAME = "myConnectorManager1";
  private static final String CM1_URL = "http://myConnectorManager1.example.com";
  private static final String CONNECTOR1 = "connector1";
  private static final String CONNECTOR2 = "connector2";
  private static final ImmutableSet<String> CONNECTOR_GROUPS_1 = ImmutableSet.of("eng", "lp");
  private static final ImmutableSet<String> CONNECTOR_GROUPS_2 = ImmutableSet.of("sales", "lp");

  private static final String GROUP1 = "Group1";
  private static final String NAMESPACE1 = "Default";
  private static final String DOMAIN1 = "group1.company.com";
  private static final String GROUP2 = "Group2";
  private static final String NAMESPACE2 = "Default";
  private static final String DOMAIN2 = "group2.company.com";
  private static final String GROUP3 = "Group3";
  private static final String NAMESPACE3 = "Default";
  private static final String DOMAIN3 = "group3.company.com";
  private static final String SUPERGROUP1 = "supergroup1";
  private static final String SUPERGROUP1_NAMESPACE = "Default";
  private static final String SUPERGROUP1_DOMAIN = "supergroup1.company.com";
  private static final String SUPERGROUP2 = "supergroup2";
  private static final String SUPERGROUP2_NAMESPACE = "Default";
  private static final String SUPERGROUP2_DOMAIN = "supergroup2.company.com";
  private static final String SUPERGROUP3 = "supergroup3";
  private static final String SUPERGROUP3_NAMESPACE = "Default";
  private static final String SUPERGROUP3_DOMAIN = "supergroup3.company.com";
  private static final String SUPERGROUP4 = "supergroup4";
  private static final String SUPERGROUP4_NAMESPACE = "Default";
  private static final String SUPERGROUP4_DOMAIN = "supergroup4.company.com";
  private static final String SUPERGROUP5 = "supergroup5";
  private static final String SUPERGROUP5_NAMESPACE = "Default";
  private static final String SUPERGROUP5_DOMAIN = "supergroup5.company.com";
  private static final String SUPERGROUP6 = "supergroup6";
  private static final String SUPERGROUP6_NAMESPACE = "Default";
  private static final String SUPERGROUP6_DOMAIN = "supergroup6.company.com";

  // In saml_groups.info, both GROUP1 and GROUP2 has member of KERBEROS_USER.
  // In saml_groups_feed.info, GROUP3 has member of KERBEROS_USER.
  private static final String GROUPSFILENAME = FileUtil.getContextDirectory()
      + "/" + "saml_groups.info";
  private static final String GROUPSFEEDFILENAME = FileUtil.getContextDirectory()
      + "/" + "saml_groups_feed.info";
  private static final ImmutableSet<Group> KERBEROS_USER_GROUPS =
      ImmutableSet.<Group>of(
          Group.make(GROUP1, NAMESPACE1, DOMAIN1),
          Group.make(GROUP2, NAMESPACE2, DOMAIN2),
          Group.make(GROUP3, NAMESPACE3, DOMAIN3));

  // In saml_groups_2.info, SUPERGROUP1 has member of group1, SUPERGROUP2 has member of group2.
  // SUPERGROUP3 has member of group3. In saml_groups_feed_2.info, SUPERGROUP4 has member of eng.
  // SUPERGROUP5 has member of sales. SUPERGROUP6 has member of lp.
  private static final String GROUPSFILENAME_2 = FileUtil.getContextDirectory()
      + "/" + "saml_groups_2.info";
  private static final String GROUPSFEEDFILENAME_2 = FileUtil.getContextDirectory()
      + "/" + "saml_groups_feed_2.info";
  private static final ImmutableSet<Group> GROUPS_1 =
      ImmutableSet.<Group>of(
          Group.make(SUPERGROUP1, SUPERGROUP1_NAMESPACE, SUPERGROUP1_DOMAIN),
          Group.make(SUPERGROUP2, SUPERGROUP2_NAMESPACE, SUPERGROUP2_DOMAIN),
          Group.make(SUPERGROUP3, SUPERGROUP3_NAMESPACE, SUPERGROUP3_DOMAIN),
          Group.make("group1", "group1"),
          Group.make("group2", "group1"),
          Group.make("group3", "group1"));
  private static final ImmutableSet<Group> GROUPS_2 =
      ImmutableSet.<Group>of(
          Group.make(SUPERGROUP4, SUPERGROUP4_NAMESPACE, SUPERGROUP4_DOMAIN),
          Group.make(SUPERGROUP5, SUPERGROUP5_NAMESPACE, SUPERGROUP5_DOMAIN),
          Group.make(SUPERGROUP6, SUPERGROUP6_NAMESPACE, SUPERGROUP6_DOMAIN),
          Group.make("eng", MockCMAuthServer.DEFAULT_GROUPS_NS),
          Group.make("sales", MockCMAuthServer.DEFAULT_GROUPS_NS),
          Group.make("lp", MockCMAuthServer.DEFAULT_GROUPS_NS));
  private static final ImmutableSet<Group> GROUPS_TOTAL =
      ImmutableSet.<Group>of(
          Group.make(SUPERGROUP1, SUPERGROUP1_NAMESPACE, SUPERGROUP1_DOMAIN),
          Group.make(SUPERGROUP2, SUPERGROUP2_NAMESPACE, SUPERGROUP2_DOMAIN),
          Group.make(SUPERGROUP3, SUPERGROUP3_NAMESPACE, SUPERGROUP3_DOMAIN),
          Group.make(SUPERGROUP4, SUPERGROUP4_NAMESPACE, SUPERGROUP4_DOMAIN),
          Group.make(SUPERGROUP5, SUPERGROUP5_NAMESPACE, SUPERGROUP5_DOMAIN),
          Group.make(SUPERGROUP6, SUPERGROUP6_NAMESPACE, SUPERGROUP6_DOMAIN),
          Group.make("group1", "group1"),
          Group.make("group2", "group1"),
          Group.make("group3", "group1"),
          Group.make("eng", MockCMAuthServer.DEFAULT_GROUPS_NS),
          Group.make("sales", MockCMAuthServer.DEFAULT_GROUPS_NS),
          Group.make("lp", MockCMAuthServer.DEFAULT_GROUPS_NS));

  private final MockIntegration integration;

  private final MockFormAuthServer fas1;
  private final MockFormAuthServer fas2;
  private final MockFormAuthServer bfas3;
  private final MockFormAuthServer fas4;
  private final MockFormAuthServer fas5;
  private final MockAlternateServiceProvider asp1;
  private final MockAlternateServiceProvider asp2;
  private final MockAlternateServiceProvider asp3;
  private final MockAlternateServiceProvider asp4;

  private final SlowHostTracker slowHostTracker;

  private MockSessionManagerBackend smBackend;
  private boolean haveSession;

  public SamlSsoTest()
      throws IOException, ServletException {
    integration = MockIntegration.make();

    // Make mock form-auth servers.
    fas1 = integration.getMockFormAuthServer();
    fas2 = new MockFormAuthServer.Form2(FORM2_CONTEXT_URL);
    bfas3 = new MockFormAuthServer.Basic1(FORM3_CONTEXT_URL);
    fas4 = new MockFormAuthServer.Form2(FORM4_CONTEXT_URL);
    fas5 = new MockFormAuthServer.Form1(FORM5_CONTEXT_URL, true);
    asp1 = makeAltSp(1, SAMLConstants.SAML2_POST_BINDING_URI, clientSigningCredential());
    asp2 = makeAltSp(2, SAMLConstants.SAML2_POST_BINDING_URI, null);
    asp3 = makeAltSp(3, SAMLConstants.SAML2_ARTIFACT_BINDING_URI, clientSigningCredential());
    asp4 = makeAltSp(4, SAMLConstants.SAML2_ARTIFACT_BINDING_URI, null);
    integration.addMockServer(fas2);
    integration.addMockServer(bfas3);
    integration.addMockServer(fas4);
    integration.addMockServer(fas5);
    integration.addMockServer(asp1);
    integration.addMockServer(asp2);
    integration.addMockServer(asp3);
    integration.addMockServer(asp4);

    slowHostTracker = ConfigSingleton.getInstance(SlowHostTracker.class);
  }

  private MockAlternateServiceProvider makeAltSp(int n, String binding,
      Credential signingCredential) {
    return new MockAlternateServiceProvider(
        ALT_SP_ENTITY_ROOT + n + "/",
        integration.getGsaHost(),
        "http://altsp" + n + HOST_DOMAIN,
        binding,
        signingCredential);
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    integration.reset();
    slowHostTracker.clearAllRecords();

    smBackend = new MockSessionManagerBackend();
    SessionUtil.setGsaSessionManager(new SessionManagerBase(smBackend));

    haveSession = false;

    addTearDown(new TearDown() {
      @Override
      public void tearDown() throws Exception {
        // If we have a session established, clean it up upon teardown..
        if (haveSession) {
          try {
            smBackend.deleteSession(integration.getSessionId());
          } catch (IndexOutOfBoundsException e) {
            // Don't care if the exception got deleted elsewhere...
          }
        }
        // Make sure clock is set to normal value.
        DateTimeUtils.setCurrentMillisSystem();
      }
    });
  }

  // -------------------------------------------------------
  // Test filling in the universal login form.

  public void testFillingInFormCorrectly() {
    integration.setTestName();
    integration.assertContentResult(1, trySingleGood());
    integration.assertTrustDuration(AuthnMechForm.getDefaultTrustDuration());
    integration.checkExchangeLog(makeGoodFormAuthLog());
  }

  public void testBadPassword() {
    integration.setTestName();
    integration.assertLoginFormResult(0,
        trySingleCredential(MockFormAuthServer.Form1.GOOD_USERNAME, BAD_PASSWORD));
    integration.checkExchangeLog(makeBadFormAuthLog());
  }

  public void testBadUsername() {
    integration.setTestName();
    integration.assertLoginFormResult(0,
        trySingleCredential(BAD_USERNAME, MockFormAuthServer.Form1.GOOD_PASSWORD));
    integration.checkExchangeLog(makeBadFormAuthLog());
  }

  public void testBadThenGood() {
    integration.setTestName();
    HttpExchange exchange = trySingleCredential(BAD_USERNAME, BAD_PASSWORD);
    integration.assertLoginFormResult(0, exchange);
    integration.assertContentResult(1,
        integration.processPostForm(exchange,
            singleCredentialParams(
                MockFormAuthServer.Form1.GOOD_USERNAME,
                MockFormAuthServer.Form1.GOOD_PASSWORD)));
    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(
                unsuccessfulSampleUrlCheck(SC_OK,
                    MockFormAuthServer.Form1.class.getSimpleName())),
            ulfExchange(
                sendBadCredsToAuthServer(MockFormAuthServer.Form1.class.getSimpleName())),
            ulfExchange(
                sendGoodCredsToAuthServer(MockFormAuthServer.Form1.class.getSimpleName())),
            successfulLogSuffix()));
  }

  /**
   * Tests behavior of SamlAuthn#doGet when no session cookie is sent.
   *
   * Called when a client, e.g., Connector V4, is using sec-mgr as IDP. The
   * expected behavior here is authn succeeds.
   */
  public void testSamlAuthnGetMissingSessionCookie() {
    integration.setTestName();
    integration.deleteUserAgentCookie(SessionUtil.GSA_SESSION_ID_COOKIE_NAME);
    integration.assertStatusResult(SC_OK, trySingleGood());
    integration.checkExchangeLog(makeGoodFormAuthLog());
  }

  /**
   * Tests behavior of SamlAuthn#doPost when no session cookie is sent.
   *
   * The difference between this test and the above one is the time of deleting
   * the cookie. If at the beginning of starting a search (actually, considering
   * Connector V4's case, search is not a precise term here. More generally, we
   * should use words like visitAProtectedService.), sending request without
   * GSA_SESSION_ID is ok because sec-mgr will generate one and ask user agent
   * to set on entering the ULF state. However, at any time after the moment of
   * entering ULF state, the user agent deletes the cookie, then the sec-mgr can
   * not move forward and a HTTP error will be returned.
   */
  public void testSamlAuthnPostMissingSessionCookie() {
    integration.setTestName();
    HttpExchange exchange = integration.startSearch();
    integration.assertLoginFormResult(exchange);
    // Delete cookie so it's not passed in POST.
    integration.deleteUserAgentCookie(SessionUtil.GSA_SESSION_ID_COOKIE_NAME);
    exchange = integration.processPostForm(exchange,
        singleCredentialParams(
            MockFormAuthServer.Form1.GOOD_USERNAME,
            MockFormAuthServer.Form1.GOOD_PASSWORD));
    integration.assertStatusResult(SC_INTERNAL_SERVER_ERROR, exchange);
    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(
                unsuccessfulSampleUrlCheck(SC_OK,
                    MockFormAuthServer.Form1.class.getSimpleName())),
            ulfExchange(),
            logResponse(SC_INTERNAL_SERVER_ERROR)));
  }

  /**
   * Test that a configured timeout works as expected.  First, fills in form,
   * getting verification with configured timeout.  Second, confirm that access
   * within timeout succeeds without contacting authentication server.  Third,
   * confirm that access after timeout succeeds, but contacts authentication
   * server.
   */
  public void testConfiguredTimeout() {
    integration.setTestName();
    // Fill in ULF and get access:
    integration.assertContentResult(1,
        tryFormCredentials(
            setupOneLogin(
                MockFormAuthServer.Form1.GOOD_USERNAME,
                MockFormAuthServer.Form1.GOOD_PASSWORD)));
    integration.checkExchangeLog(makeGoodFormAuthLog());

    integration.resetExchangeLog();

    // Confirm subsequent try gets access...
    integration.assertContentResult(1, integration.startSearch());
    // ...and that this happens without contacting the content server.
    integration.checkExchangeLog(unexpiredCredentialsLog());

    integration.resetExchangeLog();

    // Confirm subsequent try after timeout gets access...
    DateTimeUtils.setCurrentMillisOffset(
        AuthnMechForm.getDefaultTrustDuration() + SecurityManagerUtil.getClockSkewTime() + 1);
    integration.assertContentResult(1, integration.startSearch());
    // ...but only after contacting the content server.
    integration.checkExchangeLog(expiredCredentialsLog(SC_OK));
  }

  private static LogItem makeGoodFormAuthLog() {
    return logSequence(
        standardLogPrefix(
            unsuccessfulSampleUrlCheck(SC_OK,
                MockFormAuthServer.Form1.class.getSimpleName())),
        ulfExchange(
            sendGoodCredsToAuthServer(MockFormAuthServer.Form1.class.getSimpleName())),
        successfulLogSuffix());
  }

  private static LogItem makeBadFormAuthLog() {
    return logSequence(
        standardLogPrefix(
            unsuccessfulSampleUrlCheck(SC_OK,
                MockFormAuthServer.Form1.class.getSimpleName())),
        ulfExchange(
            sendBadCredsToAuthServer(MockFormAuthServer.Form1.class.getSimpleName())),
        unfinishedLogSuffix());
  }

  private static LogItem unexpiredCredentialsLog() {
    return logSequence(
        standardLogPrefix(),
        successfulLogSuffix());
  }

  private static LogItem expiredCredentialsLog(int status) {
    return logSequence(
        standardLogPrefix(
            successfulSampleUrlCheck(status)),
        successfulLogSuffix());
  }

  // -------------------------------------------------------
  // Test a cookie-protected content server that uses basic auth to login
  public void testBasicAuthCookies() {
    integration.setTestName();
    setupBasicAuthFormsGroup();
    integration.assertContentResult(
        trySingleCredential(
       MockFormAuthServer.Basic1.GOOD_USERNAME,
       MockFormAuthServer.Basic1.GOOD_PASSWORD));
  }

  // -------------------------------------------------------
  // Cookie forwarding tests

  public void testInboundCookieForwarding() {
    integration.setTestName();
    // Set the cookie before starting the sequence, and make sure that we
    // get the desired content and do not get the login challenge.
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME, COOKIE_VALUES.VALID);
    integration.assertContentResult(1, integration.startSearch());
    integration.checkExchangeLog(expiredCredentialsLog(SC_OK));
  }

  public void testBadInboundCookieForwarding() {
    integration.setTestName();
    // Set the wrong cookie before starting the sequence, and make sure that we
    // end up in the login form.
    integration.setUserAgentCookie("wrong-cookie-name", "unused");
    tryWithBadCookie();
  }

  private void tryWithBadCookie() {
    integration.assertLoginFormResult(integration.startSearch());
    integration.checkExchangeLog(logSequence(
        standardLogPrefix(
            unsuccessfulSampleUrlCheck(SC_OK,
                MockFormAuthServer.Form1.class.getSimpleName())),
        renderUlf()));
  }

  /**
   * Test that we receive back the content server cookie after filling in the form.
   */
  public void testOutboundCookieForwarding()
      throws IOException, ServletException {
    integration.setTestName();
    trySingleGood(putGsaInFas1Domain());
    assertTrue("No cookies found in user agent", integration.getUserAgentCookies().size() > 0);
    assertNotNull("Unable to find form server cookie",
        integration.getUserAgentCookieNamed(MockFormAuthServer.Form1.COOKIE_NAME));
  }

  private URL putGsaInFas1Domain()
      throws IOException, ServletException {
    String hostDomain
        = HttpUtil.domainNameParent(HttpUtil.urlFromString(fas1.getContextUrl()).getHost());
    String gsaInDomain = "gsa." + hostDomain;
    integration.addGsaHost(gsaInDomain);
    URL gsaSearchUrl = integration.getGsaSearchUrl(gsaInDomain);
    fas1.setCookieDomain(hostDomain);
    fas1.setCookiePath(GCookie.UNIVERSAL_PATH);
    return gsaSearchUrl;
  }

  /**
   * Simulate an IP-locked content server cookie.  Specifically, start off with
   * a cookie that is (supposedly) good for us, but not good for the appliance.
   * Ensure that we get the login form, which allows the appliance to retrieve a
   * cookie that's good for it.  Also ensure that the appliance does not attempt
   * to overwrite our original cookie (which is good for us).
   */
  public void testOutboundCookieForwardingIpLocked() {
    integration.setTestName();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME, COOKIE_VALUES.INVALID);

    // The cookie is invalid, so first attempt should yield the login form.
    integration.assertUnusedLoginForm(integration.startSearch());

    // Now fill in the form to get results.
    integration.assertContentResult(1, trySingleGood());

    // And check what happened to our cookie.
    GCookie c = integration.getUserAgentCookieNamed(MockFormAuthServer.Form1.COOKIE_NAME);
    assertNotNull("Content cookie was wrongly deleted.", c);
    assertEquals("Content cookie was wrongly changed.",
        COOKIE_VALUES.INVALID.toString(), c.getValue());
  }

  // -------------------------------------------------------
  // Test session semantics

  /**
   * Check that an initial request gets the form, and that a subsequent request
   * goes directly to the content (which checks that either a session was
   * established or that both directions of cookie forwarding are working).
   */
  public void testFullTurnAround() {
    integration.setTestName();
    trySingleGood();
    // we've already tested the first portion, so we reset the logs again here
    integration.resetExchangeLog();
    integration.assertContentResult(integration.startSearch());
    integration.checkExchangeLog(unexpiredCredentialsLog());
  }

  // -------------------------------------------------------
  // Test filling in a multi-CG ULF.

  /**
   * Confirm a login with multiple credential groups defined.
   */
  public void testMultipleGood() {
    integration.setTestName();
    integration.assertContentResult(2,
        tryFormCredentials(
            setupTwoLogins(
                MockFormAuthServer.Form1.GOOD_USERNAME, MockFormAuthServer.Form1.GOOD_PASSWORD,
                MockFormAuthServer.Form2.GOOD_USERNAME, MockFormAuthServer.Form2.GOOD_PASSWORD)));
    integration.checkExchangeLog(makeGoodMultipleFormAuthLog());
  }

  private static LogItem makeGoodMultipleFormAuthLog() {
    return logSequence(
        standardLogPrefix(
            unsuccessfulSampleUrlCheck(SC_OK, MockFormAuthServer.Form1.class.getSimpleName()),
            unsuccessfulSampleUrlCheck(SC_OK,
                MockFormAuthServer.Form2.class.getSimpleName())),
        ulfExchange(
            sendGoodCredsToAuthServer(MockFormAuthServer.Form1.class.getSimpleName()),
            sendGoodCredsToAuthServer(MockFormAuthServer.Form2.class.getSimpleName())),
        successfulLogSuffix());
  }

  public void testMultiplePartial() {
    integration.setTestName();
    integration.assertLoginFormResult(1,
        tryFormCredentials(
            setupTwoLogins(
                MockFormAuthServer.Form1.GOOD_USERNAME, MockFormAuthServer.Form1.GOOD_PASSWORD,
                MockFormAuthServer.Form2.GOOD_USERNAME, BAD_PASSWORD2)));
  }

  public void testMultipleBad() {
    integration.setTestName();
    integration.assertLoginFormResult(0,
        tryFormCredentials(
            setupTwoLogins(
                MockFormAuthServer.Form1.GOOD_USERNAME, BAD_PASSWORD,
                MockFormAuthServer.Form2.GOOD_USERNAME, BAD_PASSWORD2)));
  }

  // -------------------------------------------------------
  // Extended cookie forwarding and related tests

  public void testMultipleInboundCookieForwarding() {
    integration.setTestName();
    // Set the cookie before starting the sequence, and make sure that we
    // get the desired content and do not get the login form challenge.
    setupTwoCookies(COOKIE_VALUES.VALID, COOKIE_VALUES.VALID);
    integration.assertContentResult(2, integration.startSearch());
  }

  /**
   * If a valid in-bound cookie is set but the CG requires a user-name and
   * no cookie cracker is provided, we should get the ULF, not contents.
   */
  public void testInboundCookieForwardingWithRequiresUsername() {
    integration.setTestName();
    setupRequiresUsernameGroup();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME, COOKIE_VALUES.VALID);
    integration.assertLoginFormResult(integration.startSearch());
  }

  /**
   * Repeat the inbound cookie forwarding test, but then delete the user agent's
   * version of the cookie.  Ensure that a 2nd query re-uses the sec-mgr's
   * cached copy of the cookie (thus we do not see the login form on the 2nd
   * request), and that the sec-mgr overwrites the UA's cookie.
   */
  public void testInboundCookieForwardingUACookieExpires()
      throws IOException, ServletException {
    integration.setTestName();

    // Must put GSA in same domain as form server.
    URL searchUrl = putGsaInFas1Domain();
    integration.assertContentResult(1, trySingleGood(searchUrl));

    GCookie initialUaCookie
        = integration.getUserAgentCookieNamed(MockFormAuthServer.Form1.COOKIE_NAME);
    assertNotNull("Unable to find form server cookie", initialUaCookie);

    integration.deleteUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME);
    integration.assertContentResult(1, integration.startSearch(searchUrl));

    GCookie finalUaCookie
        = integration.getUserAgentCookieNamed(MockFormAuthServer.Form1.COOKIE_NAME);
    assertNotNull("User agent cookie was not overwritten", finalUaCookie);
    assertEquals("User agent cookie was wrongly changed",
        initialUaCookie.getValue(), finalUaCookie.getValue());
  }

  /**
   * Start with valid inbound cookie forwarding, but with a cookie whose value
   * is only valid once.  Ensure that the first query does not see the login
   * form, and the 2nd query does.
   */
  public void testCookieExpiration() {
    integration.setTestName();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME, COOKIE_VALUES.VALID_ONCE);
    integration.assertContentResult(1, integration.startSearch());
    integration.checkExchangeLog(expiredCredentialsLog(SC_OK));

    integration.resetExchangeLog();

    DateTimeUtils.setCurrentMillisOffset(
        AuthnMechForm.getDefaultTrustDuration() + SecurityManagerUtil.getClockSkewTime() + 1);
    // Confirm subsequent try after timeout gets login form.
    tryWithBadCookie();
  }

  /**
   * Setup to require two credential groups.  Provide cookies for both, but
   * make the one for the first credential group invalid.  We should find
   * ourselves in the login form, but with the login for the 2nd credential
   * group disabled.
   */
  public void testPartialMultipleInboundCookieForwarding() {
    integration.setTestName();
    // Set the cookie before starting the sequence, and make sure that we
    // get the desired content and do not get the login form challenge.
    setupTwoCookies(COOKIE_VALUES.INVALID, COOKIE_VALUES.VALID);

    HttpExchange exchange = integration.startSearch();
    integration.assertCredGroupEnabled(1, exchange);
    integration.assertCredGroupEnabled(2, exchange);
    integration.assertCredGroupActive(1, exchange);
    integration.assertCredGroupInactive(2, exchange);
  }


  /**
   * Make sure that when a ULF is rendered because a sample URL check passed
   * but a user-name is required and not provided by a cookie cracker, that
   * we re-test the sample URL using the credentials newly provided in the ULF,
   * not the ones previously obtained by in-bound cookie forwarding.
   * See bug 2286414.
   */
  public void testSwapIdentityUponRequiresUsername() {
    integration.setTestName();
    setupRequiresUsernameGroup();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME, COOKIE_VALUES.VALID);

    // We've got a valid cookie, but no user-name, so we should get a ULF.
    HttpExchange exchange = integration.startSearch();
    integration.assertLoginFormResult(exchange);

    // Now let's populate the ULF with a user-name and an invalid
    // password.  Validation should fail and we get the ULF again.
    exchange = integration.processPostForm(exchange,
        singleCredentialParams(
            MockFormAuthServer.Form1.GOOD_USERNAME,
            BAD_PASSWORD));
    integration.assertLoginFormResult(exchange);

    // Now let's populate the ULF with good credentials, and verify that we
    // get the contents back.
    exchange = integration.processPostForm(exchange,
        singleCredentialParams(
            MockFormAuthServer.Form1.GOOD_USERNAME,
            MockFormAuthServer.Form1.GOOD_PASSWORD));
    integration.assertContentResult(1, exchange);
  }

  // -------------------------------------------------------
  // Cookie cracking tests
  // (Note that all these tests use the forms auth module.
  //  See the following section for sample url based tests.)

  /**
   * Setup a single group that requires a username and which uses a forms-auth
   * server that provides cookie cracking.  Confirm that the CG can be satisfied
   * using an inbound cookie, and that we skip the challenge form.
   *
   * This cookie emulates a in-line cookie-cracking-only content server, i.e.
   * the crack header is generated as part of the policy enforcement point in
   * the content server, not in the forms auth server.
   */
  public void testCookieCrackingCsGet() {
    integration.setTestName();
    setupRequiresUsernameGroup();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_CS_GET);
    integration.assertContentResult(1, integration.startSearch());
    assertEquals("Wrong username cracked",
        COOKIE_VALUES.CRACK_CS_GET.toString(), integration.getPvi());
  }

  /**
   * We command the content server to issue an empty cracked username, but still
   * present valid content (i.e. the sample URL check passes).  As the CG doesn't
   * require a usernmame, we should see the CG as satisfied, but no username
   * should be asserted.
   */
  public void testCookieCrackingCsGetEmpty() {
    integration.setTestName();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_CS_GET_EMPTY);
    integration.assertContentResult(1, integration.startSearch());
    assertNull("Expected null PVI", integration.getPvi());
  }

  /**
   * Same as above, but this CG requires a username, so the verification should fail.
   */
  public void testCookieCrackingCsGetEmptyRequiresUsername() {
    integration.setTestName();
    setupRequiresUsernameGroup();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_CS_GET_EMPTY);
    integration.assertLoginFormResult(0, integration.startSearch());
  }

  /**
   * Setup a single group that requires a username and which uses a forms-auth
   * server that provides cookie cracking.  Confirm that the CG can be satisfied
   * using an inbound cookie, and that we skip the challenge form.
   *
   * This cookie emulates a cookie-cracking-only web-site, i.e. it issues the
   * crack header and nothing else (no form is generated).
   */
  public void testCookieCrackingCsStop() {
    integration.setTestName();
    setupRequiresUsernameGroup();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_CS_STOP);
    integration.assertContentResult(1, integration.startSearch());
  }

  /**
   * Setup a single group that requires a username and which uses a forms-auth
   * server that provides cookie cracking.  Confirm that the CG can be satisfied
   * using an inbound cookie, and that we skip the challenge form.
   *
   * This cookie emulates a content server that emits the cookie cracking header
   * as part of the redirect to the forms-auth-server.  This probably isn't a
   * realistic scenario (usually if the CS can crack the cookie it wouldn't bother
   * to redirect and would present the content as in CRACK_CS_GET, but we want
   * to make sure we can grab the crack headers in this mode also, and that
   * the system will auto-satisfy the CG without prompting with the form).
   */
  public void testCookieCrackingCsRedir() {
    integration.setTestName();
    setupRequiresUsernameGroup();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_CS_REDIR);
    integration.assertContentResult(1, integration.startSearch());
  }

  /**
   * Setup a single group that requires a username and which uses a forms-auth
   * server that provides cookie cracking.  Confirm that the CG can be satisfied
   * using an inbound cookie, and that we skip the challenge form.
   *
   * This cookie emulates the most likely cracking scenario- the content server
   * doesn't support cookie cracking, but the forms auth server does, and it
   * generates the cracking headers in the request when the login form would
   * generally be generated.
   */
  public void testCookieCrackingFaForm() {
    integration.setTestName();
    setupRequiresUsernameGroup();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_FA_FORM);
    integration.assertContentResult(1, integration.startSearch());
  }

  /**
   * Setup a single group that requires a username and which uses a forms-auth
   * server that provides cookie cracking.  Confirm that the CG can be satisfied
   * using an inbound cookie, and that we skip the challenge form.
   *
   * This cookie is similar to CRACK_FA_FORM, but the cookie cracking forms auth
   * server will not emit the login form because the cookie was successfully
   * cracked (presumably if a cookie is crackable, the user doesn't need a login
   * form).  This also emulates a cookie-cracking-only forms auth server.
   */
  public void testCookieCrackingFaStop() {
    integration.setTestName();
    setupRequiresUsernameGroup();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_FA_STOP);
    integration.assertContentResult(1, integration.startSearch());
  }

  /**
   * Setup a single group that requires a username and which uses a forms-auth
   * server that provides cookie cracking.  Present a cookie that's valid for
   * content, but do not present the crackable cookie.  Confirm that we end
   * up at the login form, challenging for the user-name.
   */
  public void testUnsuccessfulCookieCracking() {
    integration.setTestName();
    setupRequiresUsernameGroup();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME, COOKIE_VALUES.VALID);
    integration.assertLoginFormResult(0, integration.startSearch());
  }

  /**
   * Test cookie cracking that sets both a username and a list of groups.
   */
  public void testCookieGroupCracking() {
    integration.setTestName();
    setupRequiresUsernameGroup();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_CS_GROUP_STOP);
    integration.assertContentResult(1, integration.startSearch());
    assertEquals("Did not see expected PVI",
        COOKIE_VALUES.CRACK_CS_GROUP_STOP.toString(), integration.getPvi());
    for (Verification verification : integration.getSession().getView(
        AuthnMechForm.make("mech1", fas1.getSampleUrl())).getVerifications()) {
      if (verification.isVerified()) {
        for (com.google.enterprise.secmgr.identity.Credential credential : verification
            .getCredentials()) {
          if (credential instanceof GroupMemberships) {
            GroupMemberships grpMembership = (GroupMemberships) credential;
            int size = grpMembership.getGroups().size();
            assertTrue("Wrong number of cookie-cracked groups", size == 3 || size == 6);
            break;
          }
        }
      }
    }

  }

  /**
   * Test cookie cracking that sets only a list of groups (no username).
   */
  public void testCookieGroupOnlyCracking() {
    integration.setTestName();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_CS_GROUP_ONLY_STOP);
    integration.assertContentResult(1, integration.startSearch());
    assertNull("Expected null PVI", integration.getPvi());
    assertEquals("Wrong number of cookie-cracked groups", 3,
        integration.getSession().getVerifiedGroups().size());
  }

  /**
   * Test what happens if the content server issues an empty list of groups.
   * Basically this is just to test that nothing crashes in the pipeline.
   */
  public void testCookieEmptyGroupCracking() {
    integration.setTestName();
    setupRequiresUsernameGroup();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_CS_GROUP_EMPTY_STOP);
    integration.assertContentResult(1, integration.startSearch());
    assertEquals("Did not see expected PVI",
        COOKIE_VALUES.CRACK_CS_GROUP_EMPTY_STOP.toString(), integration.getPvi());
    assertEquals("Wrong number of cookie-cracked groups", 0,
        integration.getSession().getVerifiedGroups().size());
  }

  // -------------------------------------------------------
  // Test redirect credential gatherer.

  /**
   * Test the canonical always-redirect sequence.  The sec-mgr should redirect
   * to the content server, which in this mode (CS_REDIR_VALID_ONCE) will issue
   * a valid cookie and redirect back to sec-mgr.  Sec-mgr will check the
   * sample Url (which is the content server again), and satisfy the CG.
   */

  public void testRedirectCredentialsGatherer() {
    integration.setTestName();
    setupSampleUrlGroup(fas1.getSampleUrl(), fas1.getSampleUrl());
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CS_REDIR_VALID_ONCE);
    integration.assertContentResult(1, integration.startSearch());
    integration.checkExchangeLog(makeRedirectCredentialsGathererSequenceLog());
  }

  private static LogItem makeRedirectCredentialsGathererSequenceLog() {
    return logSequence(
        standardLogPrefix(
            // initial presatisfaction check
            unsuccessfulSampleUrlCheck(SC_OK,
                MockFormAuthServer.Form1.class.getSimpleName())
        ),
        // SecMgr redirects to the content server,
        logRedirect(MockContentServer.class.getSimpleName()),
        // which sets necessary cookies and redirects back to SecMgr,
        logRedirect(SamlAuthn.class.getSimpleName(),
            // which now gets successful sample-URL check.
            successfulSampleUrlCheck(SC_PARTIAL_CONTENT)),
        successfulLogSuffix());
  }

  /**
   * If the user already has a valid cookie for the content server,
   * don't redirect at all.
   */
  public void testRedirectValidCookie() {
    integration.setTestName();
    setupSampleUrlGroup(fas1.getSampleUrl(), fas1.getSampleUrl());
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.VALID);
    integration.assertContentResult(1, integration.startSearch());
    integration.checkExchangeLog(makeValidCookieNoRedirectLog());
  }

  private static LogItem makeValidCookieNoRedirectLog() {
    return logSequence(
        standardLogPrefix(
            // initial presatisfaction check
            successfulSampleUrlCheck(SC_OK)
        ),
        successfulLogSuffix());
  }

  /**
   * Test a redirect sequence where the content server gives us an invalid
   * cookie.  This causes the sample URL check to fail.
   */
  public void testRedirectToInvalidCookie() {
    integration.setTestName();
    setupSampleUrlGroup(fas1.getSampleUrl(), fas1.getSampleUrl());
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CS_REDIR_INVALID);
    integration.assertFailureResult(integration.startSearch());
    integration.checkExchangeLog(makeRedirectToInvalidCookieLog());
  }

  private static LogItem makeRedirectToInvalidCookieLog() {
    return logSequence(
        standardLogPrefix(
            // initial presatisfaction check
            unsuccessfulSampleUrlCheck(SC_OK,
                MockFormAuthServer.Form1.class.getSimpleName())
        ),
        // SecMgr redirects to the content server,
        logRedirect(MockContentServer.class.getSimpleName()),
        // which sets the invalid cookie and redirects back to SecMgr,
        logRedirect(SamlAuthn.class.getSimpleName(),
            // which again gets unsuccessful sample-URL check.
            unsuccessfulSampleUrlCheck(SC_PARTIAL_CONTENT,
                MockFormAuthServer.Form1.class.getSimpleName()),
            // SampleUrlCheck tries again without cookies:
            unsuccessfulSampleUrlCheck(SC_PARTIAL_CONTENT,
                MockFormAuthServer.Form1.class.getSimpleName())),
        unsuccessfulLogSuffix());
  }

  /**
   * Test a cookie-cracking redirect sequence that succeeds, then expire the
   * verification and retry the sequence.  The second try should also succeed,
   * and have the correct username.  This test verifies that b/2877347 is fixed.
   */
  public void testRedirectVerificationExpiration() {
    integration.setTestName();
    // Set up a sample-URL group with a required username.
    setConfig(Lists.newArrayList(
        credGroupBuilder(0, true, false, false)
        .addMechanism(AuthnMechSampleUrl.make("mech1", fas1.getSampleUrl(), fas1.getSampleUrl()))
        .addMechanism(AuthnMechGroups.make("mechGroups"))
        .build()));
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_CS_GET);
    integration.assertContentResult(1, integration.startSearch());
    DateTimeUtils.setCurrentMillisOffset(AuthnMechSampleUrl.getDefaultTrustDuration() + 1);
    integration.assertContentResult(1, integration.startSearch());
    assertEquals("Wrong username cracked",
        COOKIE_VALUES.CRACK_CS_GET.toString(), integration.getPvi());
  }

  /**
   * On MOMA we've seen anomalous requests arriving at SamlAuthn that appear to
   * be responses to the redirect client, but which arrive while the session is
   * idle.  This test attempts to reproduce that situation.
   */
  public void testUnexpectedRedirect() {
    integration.setTestName();
    setupSampleUrlGroup(fas1.getSampleUrl(), fas1.getSampleUrl());
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CS_REDIR_VALID_ONCE);
    integration.assertContentResult(1, integration.startSearch());
    HttpExchange exchange;
    try {
      exchange = integration.getUserAgent().getExchange(integration.getSamlAuthnUrl());
      exchange.exchange();
    } catch (IOException e) {
      MockIntegration.failWithException(e);
      return;
    }
    integration.checkExchangeLog(
        logSequence(
            makeRedirectCredentialsGathererSequenceLog(),
            logGet(SamlAuthn.class.getSimpleName()),
            logForbidden()));
  }

  /**
   * Test that an expired authority cookie is replaced when the redirect
   * gatherer gets a new cookie with the same name.  Re-creates customer
   * scenario from b/3396415.
   */
  public void testRedirectExpiredCookie()
      throws IOException, ServletException {
    integration.setTestName();
    setupSampleUrlGroup(fas5.getSampleUrl(), fas5.getSampleUrl());

    // The GSA must be in the same domain as the servers.
    integration.addGsaHost(GSA_IN_HOST_DOMAIN);
    URL gsaSearchUrl = integration.getGsaSearchUrl(GSA_IN_HOST_DOMAIN);
    fas5.setCookieDomain(HOST_DOMAIN);
    fas5.setCookiePath(GCookie.UNIVERSAL_PATH);

    // Do initial exchange and get valid cookie.
    runRedirectExpiredCookieExchange(gsaSearchUrl);

    // Simulate the expiration of the session.
    integration.newSession();

    // Simulate the expiration of the cookie.
    integration.setUserAgentCookie(
        fas5.makeCookie(
            MockFormAuthServer.Form1.COOKIE_NAME,
            MockContentServer.COOKIE_VALUES.EXPIRED.toString()));

    // Start over, same user agent but different session.
    runRedirectExpiredCookieExchange(gsaSearchUrl);
  }

  private void runRedirectExpiredCookieExchange(URL gsaSearchUrl) {
    HttpExchange exchange = integration.startSearch(gsaSearchUrl);
    integration.assertFormResult(MockFormAuthServer.FORM_MATCH_STRING, exchange);
    exchange = integration.processPostForm(exchange, makeForm1GoodParams());
    integration.assertContentResult(exchange);
    integration.checkExchangeLog(makeRedirectNoCookieLog());
    GCookie cookie = integration.getUserAgentCookieNamed(MockFormAuthServer.Form1.COOKIE_NAME);
    assertNotNull(cookie);
    assertEquals(MockContentServer.COOKIE_VALUES.VALID.toString(), cookie.getValue());
  }

  private ListMultimap<String, String> makeForm1GoodParams() {
    ListMultimap<String, String> params = newParams();
    params.put(MockFormAuthServer.Form1.USERNAME_KEY, MockFormAuthServer.Form1.GOOD_USERNAME);
    params.put(MockFormAuthServer.Form1.PASSWORD_KEY, MockFormAuthServer.Form1.GOOD_PASSWORD);
    return params;
  }

  private static LogItem makeRedirectNoCookieLog() {
    return logSequence(
        standardLogPrefix(
            // initial presatisfaction check
            unsuccessfulSampleUrlCheck(SC_OK,
                MockFormAuthServer.Form1.class.getSimpleName())
        ),
        // SecMgr redirects to the content server,
        logRedirect(MockContentServer.class.getSimpleName()),
        // content server redirects to form-auth server,
        logRedirect(MockFormAuthServer.Form1.class.getSimpleName()),
        // which renders form.
        logOk(),
        // Test sends credentials to the form,
        logPost(MockFormAuthServer.Form1.class.getSimpleName()),
        // which sets the VALID cooke and redirects back to the content server,
        logRedirect(MockContentServer.class.getSimpleName()),
        // which redirects back to SecMgr,
        logRedirect(SamlAuthn.class.getSimpleName(),
            // which now gets successful sample-URL check.
            successfulSampleUrlCheck(SC_PARTIAL_CONTENT)),
        successfulLogSuffix());
  }

  // -------------------------------------------------------
  // Test kerberos credential gatherer.

  /**
   * Tests the successful kerberos challenge/response.
   */
  public void testKerberosCredentialGatheringSuccess() {
    integration.setTestName();
    setupKerberos();
    // Sends back 401 negotiate.
    integration.assertStatusResult(SC_UNAUTHORIZED, integration.startSearch());
    integration.assertContentResult(submitKerberosResponse(KERBEROS_RESPONSE_GOOD));
  }

  /**
   * Tests kerberos challenge/response where the client response is bad.
   */
  public void testKerberosCredentialGatheringFailure() {
    integration.setTestName();
    setupKerberos();
    integration.assertStatusResult(SC_UNAUTHORIZED, integration.startSearch());
    integration.assertFailureResult(submitKerberosResponse(KERBEROS_RESPONSE_BAD));
  }

  /**
   * Tests kerberos challenge/response where the client response is invalid.
   */
  public void testKerberosCredentialGatheringInvalid() {
    integration.setTestName();
    setupKerberos();
    integration.assertStatusResult(SC_UNAUTHORIZED, integration.startSearch());
    integration.assertStatusResult(SC_UNAUTHORIZED,
        submitKerberosResponse(KERBEROS_RESPONSE_INVALID));
  }

  /**
   * Tests kerberos challenge/response where the client sends no authorization.
   */
  public void testKerberosCredentialGatheringNoResponse() {
    integration.setTestName();
    setupKerberos();
    integration.assertStatusResult(SC_UNAUTHORIZED, integration.startSearch());
    integration.assertStatusResult(SC_UNAUTHORIZED, submitKerberosResponse(null));
  }

  /**
   * Sets up mock session manager and enable kerberos
   */
  private void setupKerberos() {
    smBackend.enableKerberos(true);
    setupKerberosGroup();
  }

  /**
   * Test a sample-URL module that has no redirect URL.  We'll pre-populate a
   * cookie that asks the content server to crack and then stop.  Basically this
   * is the same as testCookieCrackingCsStop(), except using a sample-URL module
   * rather than a forms auth module.
   */
  public void testSampleUrlCookieCracker() {
    integration.setTestName();
    setupSampleUrlGroup(fas1.getSampleUrl(), null);
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_CS_STOP);
    integration.assertContentResult(1, integration.startSearch());
    integration.checkExchangeLog(expiredCredentialsLog(SC_PARTIAL_CONTENT));
  }

  // -------------------------------------------------------
  // Test various edge cases and failure modes.

  /**
   * Test content server failure.  With this inbound cookie, the forms server
   * will die with a 404.  This should lead to an indeterminate status for the
   * CG and thus lead us to the login form.
   */
  public void testContentServerFailure() {
    integration.setTestName();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.SUDDEN_DEATH);
    integration.assertLoginFormResult(0, integration.startSearch());
    integration.checkExchangeLog(makeContentServerFailureLog());
  }

  private static LogItem makeContentServerFailureLog() {
    return logSequence(
        standardLogPrefix(
            // SecMgr contacts content server,
            logGet(MockContentServer.class.getSimpleName()),
            // which fails.
            logResponse(SC_NOT_FOUND)),
        unfinishedLogSuffix());
  }

  /**
   * Test failure of the forms auth server.  This is similar to above, but we
   * set the poisionous cookie during submission of the login form, thus simulating
   * failure of the forms auth server rather than the content server.
   */
  public void testFormsAuthServerFailure() {
    integration.setTestName();
    // Start the test with no cookies and get the login form back.
    HttpExchange exchange = integration.startSearch();
    integration.assertLoginFormResult(exchange);

    // Now make the content server ill.
    fas1.getContentServer().makeIll();
    exchange = integration.processPostForm(exchange,
        singleCredentialParams(
            MockFormAuthServer.Form1.GOOD_USERNAME,
            MockFormAuthServer.Form1.GOOD_PASSWORD));
    integration.assertLoginFormResult(0, exchange);
  }

  /**
   * Test with multiple CG's where one cookie is good and the other one's
   * content server fails.  We should see the login form.
   */
  public void testMultipleWithPartialFailure() {
    integration.setTestName();
    setupTwoCookies(COOKIE_VALUES.VALID, COOKIE_VALUES.SUDDEN_DEATH);
    integration.assertLoginFormResult(1, integration.startSearch());
  }

  /**
   * TODO: Test what happens if the admin gives us the login page
   * as the sample URL.
   */

  /**
   * TODO: If we decide to support it, test a forms-auth server
   * that presents the challenge in-line (with no redirects).
   */

  /**
   * Setup to require two credential groups, and provide a correct login for one,
   * and an incorrect login for the other.  Verify that we are presented with
   * the login form and that the input for the correct CG is disabled.
   */
  public void testPartialMultipleLogins() {
    integration.setTestName();
    HttpExchange exchange =
      tryFormCredentials(
          setupTwoLogins(
              MockFormAuthServer.Form1.GOOD_USERNAME, BAD_PASSWORD,
              MockFormAuthServer.Form2.GOOD_USERNAME, MockFormAuthServer.Form2.GOOD_PASSWORD));
    integration.assertCredGroupEnabled(1, exchange);
    integration.assertCredGroupDisabled(2, exchange);
    integration.assertCredGroupActive(1, exchange);
    integration.assertCredGroupInactive(2, exchange);
  }

  // Instead of returning a 401, some forms auth servers simply redirect the
  // the user agent back to the forms auth server.  Verify that the sec-mgr
  // will reprompt the user if such is the case.
  // bug b/3095517 has more details
  public void testBadLoginOnRedirectingFormAuthServer() {
    integration.setTestName();
    setupRedirectingFormsAuthGroup();
    integration.getAuthnController().setMaxPrompts(3);

    HttpExchange exchange1 =
        tryFormCredentials(
            singleCredentialParams(MockFormAuthServer.Form3.GOOD_USERNAME, BAD_PASSWORD));
    integration.assertLoginFormResult(exchange1);

    HttpExchange exchange2 =
        integration.processPostForm(exchange1,
            singleCredentialParams(MockFormAuthServer.Form3.GOOD_USERNAME, BAD_PASSWORD));
    integration.assertLoginFormResult(exchange1);

    integration.assertFailureResult(
        integration.processPostForm(exchange2,
            singleCredentialParams(MockFormAuthServer.Form3.GOOD_USERNAME, BAD_PASSWORD)));
  }

  // -------------------------------------------------------
  // ULF tests where the submission is incomplete.

  /**
   * Setup to require two credential groups, and provide a correct login for one,
   * and leave the other blank.  Verify that we do not get the login form, but
   * instead end up with the content.  Note that we count both CG's as satisfied,
   * because an optional group that's blank is considered satisfied.
   */
  public void testPartialMultipleLoginsOneBlank() {
    integration.setTestName();
    integration.assertContentResult(2,
        tryFormCredentials(
            setupTwoLogins(
                "", "",
                MockFormAuthServer.Form2.GOOD_USERNAME, MockFormAuthServer.Form2.GOOD_PASSWORD)));
  }

  /**
   * This is the same as the above test, except we leave the non-optional CG
   * blank.  We should see that we receive the login form.
   */
  public void testPartialMultipleLoginsWrongOneBlank() {
    integration.setTestName();
    integration.assertLoginFormResult(1,
        tryFormCredentials(
            setupTwoLogins(
                MockFormAuthServer.Form1.GOOD_USERNAME, MockFormAuthServer.Form1.GOOD_PASSWORD,
                "", "")));
  }

  /**
   * Test a ULF with a required CG that's filled in with bad creds, and an
   * optional CG that's left blank.  When the ULF is presented for the second
   * time, make sure the optional CG isn't disabled.
   */
  public void testUnfilledOptionalNotLocked() {
    integration.setTestName();
    HttpExchange exchange =
        tryFormCredentials(
            setupTwoLogins(
                "", "",
                MockFormAuthServer.Form2.GOOD_USERNAME, BAD_PASSWORD));
    integration.assertCredGroupEnabled(1, exchange);
    integration.assertCredGroupEnabled(2, exchange);
  }

  /**
   * Test that we get a failure after trying to log in too many times.
   */
  public void testTooManyLoginFailures() {
    integration.setTestName();
    integration.getAuthnController().setMaxPrompts(3);

    HttpExchange exchange1 =
        tryFormCredentials(
            singleCredentialParams(MockFormAuthServer.Form1.GOOD_USERNAME, BAD_PASSWORD));
    integration.assertLoginFormResult(exchange1);

    logger.info("testTooManyLoginFailures: second login submission");
    HttpExchange exchange2 =
        integration.processPostForm(exchange1,
            singleCredentialParams(MockFormAuthServer.Form1.GOOD_USERNAME, BAD_PASSWORD));
    integration.assertLoginFormResult(exchange1);

    logger.info("testTooManyLoginFailures: third login submission");
    integration.assertFailureResult(
        integration.processPostForm(exchange2,
            singleCredentialParams(MockFormAuthServer.Form1.GOOD_USERNAME, BAD_PASSWORD)));
  }

  /**
   * Test that we send a redirection when the user submits a POST request when in IDLE state, eg.
   * by hitting Back button after a successful authentication. This verifies the fix of b/8269568
   */
  public void testRedirectOnFormSubmissionInIDLEState() throws Exception {
    integration.setTestName();
    // Start a search, expect the UL form as response
    HttpExchange exchange = integration.startSearch(integration.getGsaSearchUrl());
    Element form = integration.assertLoginFormResult(exchange);

    // Fake the IDLE state (as we had successfully authenticated before)
    AuthnSession session = integration.getSession();
    ReflectionTestUtils.setField(session, "state", AuthnState.IDLE);
    integration.saveSession(session);
    integration.setFollowRedirects(false); // We need to verify the redirection response itself

    HttpExchange exchange2 = integration.processPostForm(
        form, singleCredentialParams(MockFormAuthServer.Form1.GOOD_USERNAME, BAD_PASSWORD),
        exchange.getCookies());

    // Verify the redirection back to search page
    integration.assertRedirect(exchange2, "/");

    // Verify the whole sequence
    integration.checkExchangeLog(logSequence(
        logGet(MockServiceProvider.class.getSimpleName()),
        logRedirect(SamlAuthn.class.getSimpleName(),
            logGet(MockContentServer.class.getSimpleName()),
            logRedirect(Form1.class.getSimpleName()),
            logOk()),
        logOk(),
        logPost(SamlAuthn.class.getSimpleName()),
        logResponse(HttpServletResponse.SC_FOUND)));
  }

  /**
   * Test that we get a failure after trying to log in too many times.  Similar
   * to the above, but restarts the search each time.
   */
  public void testTooManyLoginFailuresWithRestart() {
    integration.setTestName();
    integration.getAuthnController().setMaxPrompts(3);
    integration.assertUnusedLoginForm(
        trySingleCredential(
            MockFormAuthServer.Form1.GOOD_USERNAME, BAD_PASSWORD));
    integration.assertUnusedLoginForm(
        trySingleCredential(
            MockFormAuthServer.Form1.GOOD_USERNAME, BAD_PASSWORD));
    integration.assertUnusedLoginForm(
        trySingleCredential(
            MockFormAuthServer.Form1.GOOD_USERNAME, BAD_PASSWORD));
  }

  /**
   * Test CG completion -- establish a CG that requires a username (for example,
   * one that can be used with policy ACLs) and ensure correct semantics.
   */
  public void testCgRequiresUsername() {
    integration.setTestName();
    // Set up a single group with the requires username flag.
    setConfig(Lists.newArrayList(
        credGroupBuilder(0, true, true, true)
        .addMechanism(AuthnMechForm.make("mech1", fas1.getSampleUrl()))
        .addMechanism(AuthnMechGroups.make("mechGroups"))
        .build()));

    // Provide a valid cookie, but we should still get the login form.
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME, "validCookie");
    integration.assertUnusedLoginForm(integration.startSearch());

    // Now fill in the form- we should get results.
    integration.assertContentResult(1, trySingleGood());

    // Now perform a new search.  We should find that the sec-mgr has cached
    // the username and the login form is no longer needed.
    integration.assertContentResult(1, integration.startSearch());
  }

  /**
   * Make sure that rewriting is stateless.  First run a simple test with an
   * alternate URL, then run another simple test with the standard URL.  If
   * metadata rewriting is stateful, the second test will fail because it will
   * refer to the alternate URL's host instead of the standard URL's host.
   */
  public void testMetadataRewriting()
      throws IOException, ServletException {
    integration.setTestName();
    // Run a simple test with an alternate URL.
    integration.addGsaHost(ALT_GSA_HOST);
    trySingleGood(integration.getGsaSearchUrl(ALT_GSA_HOST));

    // Now run the test again with the standard URL.
    // Second test is different because we've already authenticated.
    integration.resetExchangeLog();
    integration.assertContentResult(integration.startSearch());
    integration.checkExchangeLog(unexpiredCredentialsLog());
  }

  /**
   * Force a failure in AUTHENTICATING state, then confirm that a subsequent
   * retry succeeds.
   */
  public void testFailureRecoveryAuthenticatingState()
      throws IOException {
    integration.setTestName();
    AuthnSession authnSession = integration.makeSession();
    authnSession.setForceControllerFailure(AuthnState.AUTHENTICATING);
    integration.saveSession(authnSession);

    integration.assertServerErrorResult(integration.startSearch());
    integration.assertContentResult(1, trySingleGood());
  }

  /**
   * Force a failure in IN_UL_FORM state, then confirm that a subsequent retry
   * succeeds.
   */
  public void testFailureRecoveryUlfState()
      throws IOException {
    integration.setTestName();

    AuthnSession authnSession = integration.makeSession();
    authnSession.setForceControllerFailure(AuthnState.IN_UL_FORM);
    integration.saveSession(authnSession);

    integration.assertServerErrorResult(integration.startSearch());
    integration.assertContentResult(1, trySingleGood());
  }

  /**
   * Force a failure in IN_CREDENTIALS_GATHERER state, then confirm that a
   * subsequent retry succeeds.
   */
  public void testFailureRecoveryCgState()
      throws IOException {
    integration.setTestName();
    setupSampleUrlGroup(fas1.getSampleUrl(), fas1.getSampleUrl());
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CS_REDIR_VALID_ONCE);

    AuthnSession authnSession = integration.makeSession();
    authnSession.setForceControllerFailure(AuthnState.IN_CREDENTIALS_GATHERER);
    integration.saveSession(authnSession);


    integration.assertServerErrorResult(integration.startSearch());
    // Reset the exchange log so that "recovery" sequence matches expectations.
    integration.resetExchangeLog();
    integration.assertContentResult(1, integration.startSearch());
    integration.checkExchangeLog(makeRedirectCredentialsGathererSequenceLog());
  }

  /**
   * Force controller to dispatch as IN_UL_FORM state, and confirm that it
   * recovers.
   */
  public void testFailureRecoveryForceUlfState() {
    integration.setTestName();
    forceAuthnState(AuthnState.IN_UL_FORM);
    integration.assertServerErrorResult(integration.startSearch());
    // Reset the exchange log so that "recovery" sequence matches expectations.
    integration.resetExchangeLog();
    integration.assertContentResult(1, trySingleGood());
    integration.checkExchangeLog(makeGoodFormAuthLog());
  }

  /**
   * Force controller to dispatch as IN_CREDENTIALS_GATHERER state, and confirm
   * that it recovers.
   */
  public void testFailureRecoveryForceCgState() {
    integration.setTestName();
    forceAuthnState(AuthnState.IN_CREDENTIALS_GATHERER);
    integration.assertServerErrorResult(integration.startSearch());
    // Reset the exchange log so that "recovery" sequence matches expectations.
    integration.resetExchangeLog();
    integration.assertContentResult(1, trySingleGood());
    integration.checkExchangeLog(makeGoodFormAuthLog());
  }

  private void forceAuthnState(AuthnState state) {
    integration.getAuthnController().setForceAuthnState(state);
  }

  /**
   * Test behavior with an empty configuration.
   */
  public void testNullConfiguration() {
    integration.setTestName();
    List<CredentialGroup> credentialGroups = Lists.newArrayList();
    setConfig(credentialGroups);

    integration.assertFailureResult(integration.startSearch());
    integration.checkExchangeLog(makeNullConfigurationLog());
  }

  private static LogItem makeNullConfigurationLog() {
    return logSequence(
        standardLogPrefix(),
        unsuccessfulLogSuffix());
  }

  // ---------------------------------------------------------------
  // Session management tests

  public void testRequestSpecificSessionId()
      throws IOException {
    integration.setTestName();
    // Manually construct the exchange; repeating some of the lower level code
    // here because we need access to the request.
    URL url = integration.getGsaSearchUrl();
    MockHttpServletRequest request = ServletTestUtil.makeMockHttpGet(null, url.toString());
    MockHttpClient.MockExchange mockExchange
        = integration.getUserAgent().new MockExchange(request, url);
    mockExchange.exchange();

    // Check that the sec-mgr session ID ended up with the correct name.
    assertEquals(integration.getSessionId(),
        integration.getAuthnSessionManager().findSession(request));
  }

  // ---------------------------------------------------------------
  // Authz tests.

  public void testUserCacheAuthz()
      throws IOException {
    integration.setTestName();
    FlexAuthzRule rule = new FlexAuthzRule(FlexAuthzRule.EMPTY_AUTHN_ID, AuthzMechanism.CACHE,
        "rule", FlexAuthzRule.NO_TIME_LIMIT);
    FlexAuthorizer flexAuthorizer = ConfigSingleton.getInstance(FlexAuthorizer.class);
    flexAuthorizer.addToRulesTable(rule);
    flexAuthorizer.addToRoutingTable(
        new FlexAuthzRoutingTableEntry("http://www.end2end-cache-test.com/", rule));
    ConfigSingleton.getConfig().setFlexAuthorizer(flexAuthorizer);

    // Make sure there's a session for this ID.
    AuthnSession authnSession = integration.makeSession();
    integration.saveSession(authnSession);
    String sessionId = authnSession.getSessionId();

    Metadata metadata = integration.getMetadata();
    String localEntityId = C.entityIdForGsa(SecurityManagerTestCase.GSA_TESTING_ISSUER);
    String peerEntityId = Metadata.getSmEntityId();

    MockRelyingParty mockRelyingPartyStandard
        = new MockRelyingParty(metadata, localEntityId, peerEntityId,
            SamlAuthzClient.Protocol.STANDARD);
    MockRelyingParty mockRelyingPartyBatch1
        = new MockRelyingParty(metadata, localEntityId, peerEntityId,
            SamlAuthzClient.Protocol.BATCH_V1);
    MockRelyingParty mockRelyingPartyBatch2
        = new MockRelyingParty(metadata, localEntityId, peerEntityId,
            SamlAuthzClient.Protocol.BATCH_V2);

    String url1 = "http://www.end2end-cache-test.com/howto.txt";
    String url2 = "http://www.end2end-cache-test.com/news.html";
    List<String> urls = Lists.newArrayList(url1, url2);
    AuthzResult authzResult = mockRelyingPartyStandard.authorize(urls, sessionId);

    assertEquals("Wrong result count", 2, authzResult.size());
    assertEquals("Wrong authz status", AuthzStatus.INDETERMINATE, authzResult.get(url1));
    assertEquals("Wrong authz status", AuthzStatus.INDETERMINATE, authzResult.get(url2));

    AuthzResult authzResultBatch1 = mockRelyingPartyBatch1.authorize(urls, sessionId);
    assertEquals(authzResult, authzResultBatch1);

    AuthzResult authzResultBatch2 = mockRelyingPartyBatch2.authorize(urls, sessionId);
    assertEquals(authzResult, authzResultBatch2);

    AuthzCacheModule cache = ConfigSingleton.getInstance(AuthzCacheModule.class);

    cache.rememberPermit(url1, sessionId);
    cache.rememberDeny(url2, sessionId);
    authzResult = mockRelyingPartyStandard.authorize(urls, sessionId);

    assertEquals("Wrong result count", 2, authzResult.size());
    assertEquals("Wrong authz status", AuthzStatus.PERMIT, authzResult.get(url1));
    assertEquals("Wrong authz status", AuthzStatus.DENY, authzResult.get(url2));

    authzResultBatch1 = mockRelyingPartyBatch1.authorize(urls, sessionId);
    assertEquals(authzResult, authzResultBatch1);

    authzResultBatch2 = mockRelyingPartyBatch2.authorize(urls, sessionId);
    assertEquals(authzResult, authzResultBatch2);
  }

  public void testSimpleAuthz()
      throws IOException {
    integration.setTestName();
    assertEquals(AuthzStatus.PERMIT, trySimpleAuthz());
  }

  public void testSlowHostException()
      throws IOException {
    integration.setTestName();
    updateConfigParams(
        new ConfigParamsUpdater() {
          @Override
          public void apply(ConfigParams.Builder builder) {
            builder.put(ParamName.SLOW_HOST_TRACKER_ENABLED, true);
          }
        });

    // Mark the host as slow.
    URL url = new URL(integration.getMockFormAuthServer().getSampleUrl());
    slowHostTracker.markAsUnresponsive(url.getHost());

    assertEquals(AuthzStatus.INDETERMINATE, trySimpleAuthz());
  }

  private AuthzStatus trySimpleAuthz()
      throws IOException {

    String urlString = integration.getMockFormAuthServer().getSampleUrl();

    // Make sure there's a verified username/password available, and a cookie.
    AuthnSession session = integration.makeSession();
    AuthnMechanism mech = session.getMechanisms().get(0);
    AuthnAuthority authority = mech.getAuthority();
    session.addVerification(authority,
        Verification.verified(Verification.NEVER_EXPIRES,
            AuthnPrincipal.make(MockFormAuthServer.Form1.GOOD_USERNAME,
                session.getView(mech).getCredentialGroup().getName()),
            CredPassword.make(MockFormAuthServer.Form1.GOOD_PASSWORD)));
    session.addCookie(authority,
        GCookie.make(
            MockFormAuthServer.Form1.COOKIE_NAME,
            MockContentServer.COOKIE_VALUES.VALID.toString()));
    integration.saveSession(session);

    return integration.doAuthzQuery(urlString, session);
  }

  // ---------------------------------------------------------------
  // AuthnController sequencing tests

  /**
   * Tests that authentication modules are run after credentials gathering, even
   * if all credential groups are satisfied.  Does this by setting up a
   * credential group with a kerberos mechanism and a groups-only connector
   * mechanism, then confirming that the connector groups are properly
   * collected.
   */
  public void testDependentAuthnModule()
      throws ServletException, IOException {
    integration.setTestName();

    AuthnMechanism mech1 = AuthnMechKerberos.make("mech1");
    AuthnMechanism mech2 = AuthnMechConnector.make("mech2", CONNECTOR1, true);
    SecurityManagerConfig config
        = makeConfig(
            Lists.newArrayList(
                credGroupBuilder(0, true, false, false)
                .addMechanism(mech1)
                .addMechanism(mech2)
                .build()));
    ConfigSingleton.setConfig(config);

    // Set up connector manager servlets.
    MockCMAuthServer cmAuthServer1 = new MockCMAuthServer();
    for (String group : CONNECTOR_GROUPS_1) {
      cmAuthServer1.addGroup(CONNECTOR1, KERBEROS_USERNAME, KERBEROS_DOMAIN, group);
    }
    integration.getHttpTransport().registerServlet(
        CM1_URL + ConnectorUtil.CM_AUTHENTICATE_SERVLET_PATH,
        cmAuthServer1);
    integration.getHttpTransport().registerServlet(
        CM1_URL + ConnectorUtil.CM_INSTANCE_LIST_SERVLET_PATH,
        new MockGetConnectorInstanceList(ImmutableList.of(CONNECTOR1)));
    updateConfigParams(
        new ConfigParamsUpdater() {
          @Override
          public void apply(ConfigParams.Builder builder) {
            builder.put(ParamName.CONNECTOR_MANAGER_INFO,
                ConnMgrInfo.make(
                    ImmutableList.of(
                        ConnMgrInfo.Entry.make(CM1_NAME, CM1_URL))));
          }
        });

    smBackend.enableKerberos(true);
    integration.assertStatusResult(SC_UNAUTHORIZED, integration.startSearch());
    integration.assertContentResult(submitKerberosResponse(KERBEROS_RESPONSE_GOOD));
    assertEquals(stringToGroup(CONNECTOR_GROUPS_1, MockCMAuthServer.DEFAULT_GROUPS_NS, null),
        integration.getSession().getVerifiedGroups());
    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(),
            logResponse(SC_UNAUTHORIZED),
            logGet(SamlAuthn.class.getSimpleName(),
                logPost(MockGetConnectorInstanceList.class.getSimpleName()),
                logOk(),
                logPost(MockCMAuthServer.class.getSimpleName()),
                logOk()),
            successfulLogSuffix()));
  }

  /**
   * Tests scenario with two optional credential groups, one of which uses ULF,
   * and the other uses a credentials gatherer (Kerberos in this test).  The ULF
   * is filled out with good credentials, and the credentials gatherer is given
   * no credentials.  This is expected to produce a successful authentication.
   * This is a regression test for b/5573009.
   */
  public void testSatisfaction()
      throws IOException {
    integration.setTestName();

    AuthnMechanism mech1 = AuthnMechKerberos.make("mech1");
    AuthnMechanism mech2 = AuthnMechForm.make("mech2", fas1.getSampleUrl());
    SecurityManagerConfig config
        = makeConfig(
            Lists.newArrayList(
                credGroupBuilder(0, false, false, true)
                .addMechanism(mech1)
                .addMechanism(AuthnMechGroups.make("mechGroups"))
                .build(),
                credGroupBuilder(1, false, false, true)
                .addMechanism(mech2)
                .addMechanism(AuthnMechGroups.make("mechGroups1"))
                .build()));
    ConfigSingleton.setConfig(config);

    smBackend.enableKerberos(true);
    integration.assertStatusResult(SC_UNAUTHORIZED, integration.startSearch());
    HttpExchange exchange = submitKerberosResponse(KERBEROS_RESPONSE_INVALID);
    integration.assertLoginFormResult(exchange);
    exchange = integration.processPostForm(exchange,
        singleCredentialParams(
            MockFormAuthServer.Form1.GOOD_USERNAME,
            MockFormAuthServer.Form1.GOOD_PASSWORD));
    integration.assertContentResult(exchange);

    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(
                unsuccessfulSampleUrlCheck(SC_OK,
                    MockFormAuthServer.Form1.class.getSimpleName())),
            logResponse(SC_UNAUTHORIZED),
            logGet(SamlAuthn.class.getSimpleName()),
            ulfExchange(
                sendGoodCredsToAuthServer(MockFormAuthServer.Form1.class.getSimpleName())),
            successfulLogSuffix()));
  }

  /**
   * Tests that all "ready" modules are run even if running one of them makes
   * another one "satisfied".  Regression test for b/5570322.
   */
  public void testRunAllReadyModules()
      throws ServletException, IOException {
    integration.setTestName();

    AuthnMechanism mech1 = AuthnMechKerberos.make("mech1");
    AuthnMechanism mech2 = AuthnMechConnector.make("mech2", CONNECTOR1, true);
    AuthnMechanism mech3 = AuthnMechConnector.make("mech3", CONNECTOR2, true);
    SecurityManagerConfig config
        = makeConfig(
            Lists.newArrayList(
                credGroupBuilder(0, true, false, false)
                .addMechanism(mech1)
                .addMechanism(mech2)
                .addMechanism(mech3)
                .build()));
    ConfigSingleton.setConfig(config);

    // Set up connector manager servlets.
    MockCMAuthServer cmAuthServer1 = new MockCMAuthServer();
    for (String group : CONNECTOR_GROUPS_1) {
      cmAuthServer1.addGroup(CONNECTOR1, KERBEROS_USERNAME, KERBEROS_DOMAIN, group);
    }
    for (String group : CONNECTOR_GROUPS_2) {
      cmAuthServer1.addGroup(CONNECTOR2, KERBEROS_USERNAME, KERBEROS_DOMAIN, group);
    }
    integration.getHttpTransport().registerServlet(
        CM1_URL + ConnectorUtil.CM_AUTHENTICATE_SERVLET_PATH,
        cmAuthServer1);
    integration.getHttpTransport().registerServlet(
        CM1_URL + ConnectorUtil.CM_INSTANCE_LIST_SERVLET_PATH,
        new MockGetConnectorInstanceList(ImmutableList.of(CONNECTOR1, CONNECTOR2)));
    updateConfigParams(
        new ConfigParamsUpdater() {
          @Override
          public void apply(ConfigParams.Builder builder) {
            builder.put(ParamName.CONNECTOR_MANAGER_INFO,
                ConnMgrInfo.make(
                    ImmutableList.of(
                        ConnMgrInfo.Entry.make(CM1_NAME, CM1_URL))));
          }
        });

    smBackend.enableKerberos(true);
    integration.assertStatusResult(SC_UNAUTHORIZED, integration.startSearch());
    integration.assertContentResult(submitKerberosResponse(KERBEROS_RESPONSE_GOOD));

    Set<Group> allGroups = ImmutableSet.<Group>builder()
        .addAll(stringToGroup(CONNECTOR_GROUPS_1, MockCMAuthServer.DEFAULT_GROUPS_NS, null))
        .addAll(stringToGroup(CONNECTOR_GROUPS_2, MockCMAuthServer.DEFAULT_GROUPS_NS, null))
        .build();

    assertEquals(allGroups, integration.getSession().getVerifiedGroups());
    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(),
            logResponse(SC_UNAUTHORIZED),
            logGet(SamlAuthn.class.getSimpleName(),
                logPost(MockGetConnectorInstanceList.class.getSimpleName()),
                logOk(),
                logPost(MockCMAuthServer.class.getSimpleName()),
                logOk(),
                logPost(MockCMAuthServer.class.getSimpleName()),
                logOk()),
            successfulLogSuffix()));
  }

  public void testModuleGroups()
      throws IOException {
    integration.setTestName();

    AuthnMechanism mech1 = AuthnMechKerberos.make("mech1");
    AuthnMechanism mech2 = AuthnMechGroups.make("groups", AuthnMechanism.NO_TIME_LIMIT,
        AuthnMechGroups.getDefaultTrustDuration());
    SecurityManagerConfig config =
        makeConfig(Lists.newArrayList(
            credGroupBuilder(0, true, false, false)
            .addMechanism(mech1)
            .addMechanism(mech2)
            .build()));
    ConfigSingleton.setConfig(config);

    smBackend.enableKerberos(true);
    GroupsUpdateModule groups = ConfigSingleton.getInstance(GroupsUpdateModule.class);
    groups.forceOverrideMembershipDataForTest(GROUPSFILENAME, GROUPSFEEDFILENAME);

    integration.assertStatusResult(SC_UNAUTHORIZED, integration.startSearch());
    integration.assertContentResult(submitKerberosResponse(KERBEROS_RESPONSE_GOOD));

    assertEquals(KERBEROS_USER_GROUPS, integration.getSession().getView(mech2).getVerifiedGroups());
  }

  public void testMultipleAuthnModulesWithGroups()
      throws ServletException, IOException {
    integration.setTestName();
    AuthnMechanism groupsMech1 =
        AuthnMechGroups.make("groups_1", AuthnMechanism.NO_TIME_LIMIT,
            AuthnMechGroups.getDefaultTrustDuration());
    AuthnMechForm formMech =
        AuthnMechForm.make("form", fas1.getSampleUrl());


    AuthnMechanism groupsMech2 =
        AuthnMechGroups.make("groups_2", AuthnMechanism.NO_TIME_LIMIT,
            AuthnMechGroups.getDefaultTrustDuration());
    AuthnMechanism kerberosMech = AuthnMechKerberos.make("kerberos");
    AuthnMechanism connectorMech1 = AuthnMechConnector.make("connector1", CONNECTOR1, true);
    AuthnMechanism connectorMech2 = AuthnMechConnector.make("connector2", CONNECTOR2, true);

    CredentialGroup cg1 =
        credGroupBuilder(0, true, false, false)
          .addMechanism(groupsMech1)
          .addMechanism(formMech)
          .build();
    CredentialGroup cg2 =
        credGroupBuilder(1, true, false, false)
          .addMechanism(groupsMech2)
          .addMechanism(kerberosMech)
          .addMechanism(connectorMech1)
          .addMechanism(connectorMech2)
          .build();

    SecurityManagerConfig config
        = makeConfig(Lists.newArrayList(cg1, cg2));

    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME,
        COOKIE_VALUES.CRACK_CS_GROUP_STOP);


    ConfigSingleton.setConfig(config);

    // Set up connector manager servlets.
    MockCMAuthServer cmAuthServer1 = new MockCMAuthServer();
    for (String group : CONNECTOR_GROUPS_1) {
      cmAuthServer1.addGroup(CONNECTOR1, KERBEROS_USERNAME, KERBEROS_DOMAIN, group);
    }
    for (String group : CONNECTOR_GROUPS_2) {
      cmAuthServer1.addGroup(CONNECTOR2, KERBEROS_USERNAME, KERBEROS_DOMAIN, group);
    }
    integration.getHttpTransport().registerServlet(
        CM1_URL + ConnectorUtil.CM_AUTHENTICATE_SERVLET_PATH,
        cmAuthServer1);
    integration.getHttpTransport().registerServlet(
        CM1_URL + ConnectorUtil.CM_INSTANCE_LIST_SERVLET_PATH,
        new MockGetConnectorInstanceList(ImmutableList.of(CONNECTOR1, CONNECTOR2)));
    updateConfigParams(
        new ConfigParamsUpdater() {
          @Override
          public void apply(ConfigParams.Builder builder) {
            builder.put(ParamName.CONNECTOR_MANAGER_INFO,
                ConnMgrInfo.make(
                    ImmutableList.of(
                        ConnMgrInfo.Entry.make(CM1_NAME, CM1_URL))));
          }
        });

    GroupsUpdateModule groups = ConfigSingleton.getInstance(GroupsUpdateModule.class);
    groups.forceOverrideMembershipDataForTest(GROUPSFILENAME_2, GROUPSFEEDFILENAME_2);

    smBackend.enableKerberos(true);
    integration.startSearch();
    integration.assertContentResult(submitKerberosResponse(KERBEROS_RESPONSE_GOOD));

    assertEquals(GROUPS_1, integration.getSession().getView(groupsMech1).getVerifiedGroups());
    assertEquals(GROUPS_2, integration.getSession().getView(groupsMech2).getVerifiedGroups());
    assertEquals(GROUPS_TOTAL, integration.getSession().getVerifiedGroups());
  }

  public void testModuleGroupsRefuted()
      throws IOException {
    integration.setTestName();

    AuthnMechanism mech1 = AuthnMechKerberos.make("mech1");
    AuthnMechanism mech2 = AuthnMechGroups.make("groups", AuthnMechanism.NO_TIME_LIMIT,
        AuthnMechGroups.getDefaultTrustDuration());
    SecurityManagerConfig config =
        makeConfig(Lists.newArrayList(
            credGroupBuilder(0, true, false, false)
            .addMechanism(mech1)
            .addMechanism(mech2)
            .build()));
    ConfigSingleton.setConfig(config);

    smBackend.enableKerberos(true);
    GroupsUpdateModule groups = ConfigSingleton.getInstance(GroupsUpdateModule.class);
    groups.forceOverrideMembershipDataForTest(GROUPSFILENAME, GROUPSFEEDFILENAME);

    integration.assertStatusResult(SC_UNAUTHORIZED, integration.startSearch());
    integration.assertFailureResult(submitKerberosResponse(KERBEROS_RESPONSE_BAD));
    assertEquals(0, integration.getSession().getView(mech2).getVerifiedGroups().size());
  }


  /**
   * Tests the runnability status of module which does group resolution is READY
   * even when the previous/other module which was run returns groups.
   * Also tests that Verfication with only GroupMembership does not remove other
   * verifications which contains groups.
   * Regression test for b/6512358.
   */
  public void testModuleDependencyWithMergingGroups() throws ServletException {
    integration.setTestName();
    AuthnMechanism mech1 = AuthnMechConnector.make("mech1", CONNECTOR1, false);
    AuthnMechanism mech2 = AuthnMechConnector.make("mech2", CONNECTOR2, true);
    SecurityManagerConfig config
        = makeConfig(
            Lists.newArrayList(
                credGroupBuilder(0, true, false, false)
                .addMechanism(mech1)
                .addMechanism(mech2)
                .build()));
    ConfigSingleton.setConfig(config);

    // Set up connector manager servlets.
    MockCMAuthServer cmAuthServer1 = new MockCMAuthServer();
    cmAuthServer1.setPassword(CONNECTOR1, MockFormAuthServer.Form1.GOOD_USERNAME,
        null, MockFormAuthServer.Form1.GOOD_PASSWORD);
    for (String group : CONNECTOR_GROUPS_1) {
      cmAuthServer1.addGroup(CONNECTOR1, MockFormAuthServer.Form1.GOOD_USERNAME, null, group);
    }
    for (String group : CONNECTOR_GROUPS_2) {
      cmAuthServer1.addGroup(CONNECTOR2, MockFormAuthServer.Form1.GOOD_USERNAME, null, group);
    }
    integration.getHttpTransport().registerServlet(
        CM1_URL + ConnectorUtil.CM_AUTHENTICATE_SERVLET_PATH,
        cmAuthServer1);
    integration.getHttpTransport().registerServlet(
        CM1_URL + ConnectorUtil.CM_INSTANCE_LIST_SERVLET_PATH,
        new MockGetConnectorInstanceList(ImmutableList.of(CONNECTOR1, CONNECTOR2)));
    updateConfigParams(
        new ConfigParamsUpdater() {
          @Override
          public void apply(ConfigParams.Builder builder) {
            builder.put(ParamName.CONNECTOR_MANAGER_INFO,
                ConnMgrInfo.make(
                    ImmutableList.of(
                        ConnMgrInfo.Entry.make(CM1_NAME, CM1_URL))));
          }
        });
    integration.assertUnusedLoginForm(integration.startSearch());
    trySingleGood();

    Set<Group> allGroups = ImmutableSet.<Group>builder()
        .addAll(stringToGroup(CONNECTOR_GROUPS_1, MockCMAuthServer.DEFAULT_GROUPS_NS, null))
        .addAll(stringToGroup(CONNECTOR_GROUPS_2, MockCMAuthServer.DEFAULT_GROUPS_NS, null))
        .build();
    assertEquals(MockFormAuthServer.Form1.GOOD_USERNAME,
        integration.getSession().getSnapshot().getView().getUsername());
    assertEquals(MockFormAuthServer.Form1.GOOD_PASSWORD,
        integration.getSession().getSnapshot().getView().getPassword());
    assertEquals(allGroups, integration.getSession().getVerifiedGroups());
  }

  private Set<Group> stringToGroup(Set<String> groupNames, String namespace, String domain) {
    ImmutableSet.Builder<Group> groupBuilder = ImmutableSet.builder();
    for (String name : groupNames) {
      if (!Strings.isNullOrEmpty(domain)) {
        groupBuilder.add(Group.make(name, namespace, domain));
      } else {
        groupBuilder.add(Group.make(name, namespace));
      }
    }
    return groupBuilder.build();
  }
  // ---------------------------------------------------------------
  // Alternate SAML Service Provider tests

  public void testAlternateSpPostGood()
      throws IOException {
    integration.setTestName();
    useAlternateCacerts("cacerts2.jks");
    HttpExchange exchange = trySingleGood(new URL(asp1.getSampleUrl()));
    Element form = integration.assertPostBindingResult(exchange);
    integration.assertContentResult(integration.processPostForm(form, exchange.getCookies()));
    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(MockAlternateServiceProvider.class.getSimpleName(),
                unsuccessfulSampleUrlCheck(SC_OK,
                    MockFormAuthServer.Form1.class.getSimpleName())),
            ulfExchange(
                sendGoodCredsToAuthServer(MockFormAuthServer.Form1.class.getSimpleName())),
            postLogSuffix(SC_OK, MockAlternateServiceProvider.class.getSimpleName())));
  }

  public void testAlternateSpPostBad()
      throws IOException {
    integration.setTestName();
    useAlternateCacerts("cacerts2.jks");
    integration.assertLoginFormResult(
        trySingleCredential(new URL(asp1.getSampleUrl()), BAD_USERNAME, BAD_PASSWORD));
    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(MockAlternateServiceProvider.class.getSimpleName(),
                unsuccessfulSampleUrlCheck(SC_OK,
                    MockFormAuthServer.Form1.class.getSimpleName())),
            ulfExchange(
                sendBadCredsToAuthServer(MockFormAuthServer.Form1.class.getSimpleName())),
            unfinishedLogSuffix()));
  }

  public void testAlternateSpPostNoSignature()
      throws IOException {
    integration.setTestName();
    useAlternateCacerts("cacerts2.jks");
    HttpExchange exchange = integration.startSearch(new URL(asp2.getSampleUrl()));
    Element form = integration.assertPostBindingResult(exchange);
    integration.assertServerErrorResult(integration.processPostForm(form, exchange.getCookies()));
    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(MockAlternateServiceProvider.class.getSimpleName()),
            postLogSuffix(SC_INTERNAL_SERVER_ERROR,
                MockAlternateServiceProvider.class.getSimpleName())));
  }

  public void testAlternateSpPostNoCert()
      throws IOException {
    integration.setTestName();
    HttpExchange exchange = integration.startSearch(new URL(asp1.getSampleUrl()));
    Element form = integration.assertPostBindingResult(exchange);
    integration.assertServerErrorResult(integration.processPostForm(form, exchange.getCookies()));
    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(MockAlternateServiceProvider.class.getSimpleName()),
            postLogSuffix(SC_INTERNAL_SERVER_ERROR,
                MockAlternateServiceProvider.class.getSimpleName())));
  }

  public void testAlternateSpArtifactGood()
      throws IOException {
    integration.setTestName();
    useAlternateCacerts("cacerts2.jks");
    integration.assertContentResult(trySingleGood(new URL(asp3.getSampleUrl())));
    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(MockAlternateServiceProvider.class.getSimpleName(),
                unsuccessfulSampleUrlCheck(SC_OK,
                    MockFormAuthServer.Form1.class.getSimpleName())),
            ulfExchange(
                sendGoodCredsToAuthServer(MockFormAuthServer.Form1.class.getSimpleName())),
            artifactLogSuffix(SC_OK, MockAlternateServiceProvider.class.getSimpleName())));
  }

  public void testAlternateSpArtifactBad()
      throws IOException {
    integration.setTestName();
    useAlternateCacerts("cacerts2.jks");
    integration.assertLoginFormResult(
        trySingleCredential(new URL(asp3.getSampleUrl()), BAD_USERNAME, BAD_PASSWORD));
    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(MockAlternateServiceProvider.class.getSimpleName(),
                unsuccessfulSampleUrlCheck(SC_OK,
                    MockFormAuthServer.Form1.class.getSimpleName())),
            ulfExchange(
                sendBadCredsToAuthServer(MockFormAuthServer.Form1.class.getSimpleName())),
            unfinishedLogSuffix()));
  }

  public void testAlternateSpArtifactNoSignature()
      throws IOException {
    integration.setTestName();
    useAlternateCacerts("cacerts2.jks");
    integration.assertServerErrorResult(integration.startSearch(new URL(asp4.getSampleUrl())));
    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(MockAlternateServiceProvider.class.getSimpleName()),
            artifactLogSuffix(SC_INTERNAL_SERVER_ERROR,
                MockAlternateServiceProvider.class.getSimpleName())));
  }

  public void testAlternateSpArtifactNoCert()
      throws IOException {
    integration.setTestName();
    integration.assertServerErrorResult(integration.startSearch(new URL(asp3.getSampleUrl())));
    integration.checkExchangeLog(
        logSequence(
            standardLogPrefix(MockAlternateServiceProvider.class.getSimpleName()),
            artifactLogSuffix(SC_INTERNAL_SERVER_ERROR,
                MockAlternateServiceProvider.class.getSimpleName())));
  }

  // ---------------------------------------------------------------
  // Setup helpers

  private ListMultimap<String, String> singleCredentialParams(String username, String password) {
    SecurityManagerConfig config;
    try {
      config = ConfigSingleton.getConfig();
    } catch (IOException e) {
      fail("Unable to read configuration file");
      return null;
    }
    CredentialGroup credentialGroup = null;
    for (CredentialGroup cg : config.getCredentialGroups()) {
      if (cg.canUseUlfCredentials()) {
        credentialGroup = cg;
        break;
      }
    }
    ListMultimap<String, String> params = newParams();
    addCredential(username, password, credentialGroup, params);
    return params;
  }

  /**
   * Set up one credential group, which has a single forms-auth mechanism.  Make
   * a username/password credential for the group, returning appropriate form
   * parameters to match.
   *
   * @param username1 Username for the credential group.
   * @param password1 Password for the credential group.
   * @return A list of form parameters for the ULF form submission.
   */
  private ListMultimap<String, String> setupOneLogin(String username1, String password1) {
    List<CredentialGroup> groups = setupOneCredGroup();
    ListMultimap<String, String> params = newParams();
    addCredential(username1, password1, groups.get(0), params);
    return params;
  }

  /**
   * Set up two credential groups, each of which has a single forms-auth
   * mechanism.  Make a username/password credential for each group, returning
   * appropriate form parameters to match.
   *
   * @param username1 Username for the first credential group.
   * @param password1 Password for the first credential group.
   * @param username2 Username for the second credential group.
   * @param password2 Password for the second credential group.
   * @return A list of form parameters for the ULF form submission.
   */
  private ListMultimap<String, String> setupTwoLogins(String username1, String password1,
      String username2, String password2) {
    List<CredentialGroup> groups = setupTwoCredGroups();
    ListMultimap<String, String> params = newParams();
    addCredential(username1, password1, groups.get(0), params);
    addCredential(username2, password2, groups.get(1), params);
    return params;
  }

  private static ListMultimap<String, String> newParams() {
    return ArrayListMultimap.create();
  }

  /**
   * Set up two credential groups, each of which has a single forms-auth
   * mechanism.  Provide a cookie for each group, with the given values.
   *
   * @param value1 Cookie value for the first credential group.
   * @param value2 Cookie value for the second credential group.
   */
  private void setupTwoCookies(COOKIE_VALUES value1, COOKIE_VALUES value2) {
    setupTwoCredGroups();
    integration.setUserAgentCookie(MockFormAuthServer.Form1.COOKIE_NAME, value1);
    integration.setUserAgentCookie(MockFormAuthServer.Form2.COOKIE_NAME, value2);
  }

  /**
   * Set up one credential groups, which has a single forms-auth mechanism.  The
   * group is required.
   *
   * @return A list of credential-group configurations.
   */
  private List<CredentialGroup> setupOneCredGroup() {
    return setConfig(Lists.newArrayList(
        credGroupBuilder(0, false, false, false)
        .addMechanism(AuthnMechForm.make("mech1", fas1.getSampleUrl()))
        .addMechanism(AuthnMechGroups.make("mechGroups"))
        .build()));
  }

  /**
   * Set up two credential groups, each of which has a single forms-auth
   * mechanism.  The first group is optional and the second is required.
   *
   * @return A list of credential-group configurations.
   */
  private List<CredentialGroup> setupTwoCredGroups() {
    return setConfig(Lists.newArrayList(
        credGroupBuilder(0, false, false, true)
        .addMechanism(AuthnMechForm.make("mech1", fas1.getSampleUrl()))
        .addMechanism(AuthnMechGroups.make("mechGroups"))
        .build(),
        credGroupBuilder(1, false, false, false)
        .addMechanism(AuthnMechForm.make("mech2", fas2.getSampleUrl()))
        .addMechanism(AuthnMechGroups.make("mechGroups1"))
        .build()));
  }

  private List<CredentialGroup> setupRequiresUsernameGroup() {
    return setConfig(Lists.newArrayList(
        credGroupBuilder(0, true, false, false)
        .addMechanism(AuthnMechForm.make("mech1", fas1.getSampleUrl()))
        .addMechanism(AuthnMechGroups.make("mechGroups"))
        .build()));
  }

  private List<CredentialGroup> setupBasicAuthFormsGroup() {
    return setConfig(Lists.newArrayList(
        credGroupBuilder(0, true, false, false)
        .addMechanism(AuthnMechForm.make("mech3", bfas3.getSampleUrl()))
        .addMechanism(AuthnMechGroups.make("mechGroups"))
        .build()));
  }

  private List<CredentialGroup> setupRedirectingFormsAuthGroup() {
    return setConfig(Lists.newArrayList(
        credGroupBuilder(0, true, false, false)
        .addMechanism(AuthnMechForm.make("mech4", fas4.getSampleUrl()))
        .addMechanism(AuthnMechGroups.make("mechGroups"))
        .build()));
  }

  private List<CredentialGroup> setupSampleUrlGroup(String sampleUrl, String redirectUrl) {
    return setConfig(Lists.newArrayList(
        credGroupBuilder(0, false, false, false)
        .addMechanism(AuthnMechSampleUrl.make("mech1", sampleUrl, redirectUrl))
        .addMechanism(AuthnMechGroups.make("mechGroups"))
        .build()));
  }

  private List<CredentialGroup> setupKerberosGroup() {
    return setConfig(Lists.newArrayList(
        credGroupBuilder(0, false, false, false)
        .addMechanism(AuthnMechKerberos.make("mech1"))
        .addMechanism(AuthnMechGroups.make("mechGroups"))
        .build()));
  }

  private CredentialGroup.Builder credGroupBuilder(int index, boolean requiresUsername,
      boolean requiresPassword, boolean isOptional) {
    String name = "group" + (index + 1);
    return CredentialGroup.builder(name, name + " display", requiresUsername, requiresPassword,
        isOptional);
  }

  private List<CredentialGroup> setConfig(List<CredentialGroup> credentialGroups) {
    ConfigSingleton.setConfig(makeConfig(credentialGroups));
    return credentialGroups;
  }

  private void addCredential(String username, String password,
      CredentialGroup adg, ListMultimap<String, String> params) {
    String name = adg.getName();
    params.put("u" + name, username);
    params.put("pw" + name, password);
  }

  /**
   * Sets up mock session manager and enable kerberos
   */
  private void setupSessionManager(String sessionId) {
    SessionUtil.setGsaSessionManager(new SessionManagerBase(smBackend));
    smBackend.enableKerberos(true);
    smBackend.createSession(sessionId);
    haveSession = true;
  }

  private static void useAlternateCacerts(final String filename)
      throws IOException {
    updateConfigParams(
        new ParamsUpdater() {
          @Override
          public void apply(ConfigParams.Builder builder) {
            builder.put(ParamName.CERTIFICATE_AUTHORITIES_FILENAME, filename);
          }
        });
  }

  private static void updateConfig(Function<SecurityManagerConfig, SecurityManagerConfig> updater)
      throws IOException {
    ConfigSingleton.setConfig(updater.apply(ConfigSingleton.getConfig()));
  }

  private static void updateConfigParams(final ParamsUpdater paramsUpdater)
      throws IOException {
    updateConfig(
        new Function<SecurityManagerConfig, SecurityManagerConfig>() {
          @Override
          public SecurityManagerConfig apply(SecurityManagerConfig config) {
            ConfigParams.Builder builder = ConfigParams.builder(config.getParams());
            paramsUpdater.apply(builder);
            return SecurityManagerConfig.make(
                config.getCredentialGroups(),
                builder.build(),
                config.getFlexAuthorizer());
          }
        });
  }

  private interface ParamsUpdater {
    public void apply(ConfigParams.Builder builder);
  }

  // ---------------------------------------------------------------
  // Testing helpers

  private HttpExchange trySingleGood() {
    return trySingleGood(integration.getGsaSearchUrl());
  }

  private HttpExchange trySingleGood(URL searchUrl) {
    return trySingleCredential(searchUrl,
        MockFormAuthServer.Form1.GOOD_USERNAME,
        MockFormAuthServer.Form1.GOOD_PASSWORD);
  }

  private HttpExchange trySingleCredential(String username, String password) {
    return trySingleCredential(integration.getGsaSearchUrl(), username, password);
  }

  private HttpExchange trySingleCredential(URL searchUrl, String username, String password) {
    return tryFormCredentials(searchUrl, singleCredentialParams(username, password));
  }

  private HttpExchange tryFormCredentials(ListMultimap<String, String> params) {
    return tryFormCredentials(integration.getGsaSearchUrl(), params);
  }

  private HttpExchange tryFormCredentials(URL searchUrl, ListMultimap<String, String> params) {
    HttpExchange exchange = integration.startSearch(searchUrl);
    if (params.size() > 0) {
      integration.assertLoginFormResult(exchange);
    } else {
      integration.assertExchangeStatusOk(exchange);
    }
    return integration.processPostForm(exchange, params);
  }

  /**
   * Sends out a mock http client kerberos challenge response back to security manager.
   *
   * @param response The kerberos authorization header
   */
  private HttpExchange submitKerberosResponse(String response) {
    try {
      MockHttpClient.MockExchange exchange = MockHttpClient.MockExchange.class.cast(
          integration.getUserAgent().getExchange(integration.getSamlAuthnUrl()));
      exchange.setKerberosCredential(response);
      exchange.setFollowRedirects(true);
      exchange.exchange();
      return exchange;
    } catch (IOException e) {
      MockIntegration.failWithException(e);
      return null;
    }
  }

  private static Credential clientSigningCredential()
      throws IOException {
    return OpenSamlUtil.readX509Credential(
        FileUtil.getContextFile("saml-client-test.crt"),
        FileUtil.getContextFile("saml-client-test.key"));
  }
}
