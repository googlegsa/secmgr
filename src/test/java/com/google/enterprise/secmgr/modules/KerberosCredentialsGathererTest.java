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

import static com.google.common.truth.Truth.assertThat;

import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.CredentialsGathererElement;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.CookieStore;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.common.Stringify;
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.AuthnMechKerberos;
import com.google.enterprise.secmgr.config.AuthnMechNtlm;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.mock.MockIntegration;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.enterprise.sessionmanager.KerberosId;
import com.google.enterprise.sessionmanager.SessionManagerInterfaceBase;
import java.io.IOException;
import java.net.URL;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import org.easymock.EasyMock;
import org.easymock.IMocksControl;
import org.joda.time.DateTimeUtils;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Tests Kerberos Credential gathering.
 *
 */
public class KerberosCredentialsGathererTest extends SecurityManagerTestCase {
  private static final DateTimeFormatter ISO8601_FORMAT = ISODateTimeFormat.dateTime();
  private static final String SAMPLE_URL = "http://localhost/domain1/sample";
  private static final String REALM_NAME = "realmName";
  private static final String SERVER_NAME = "serverName@" + REALM_NAME;
  private static final String USER_NAME = "userName";
  private static final String USER_AND_REALM = USER_NAME + "@" + REALM_NAME;
  private static final String SESSION_ID = "id";
  private static final String DUMMY_RESPONSE = "dummyKerberosResponse";

  private final MockIntegration integration;

  private IMocksControl control;
  private CredentialsGathererElement mockElement;
  private AuthnAuthority mockAuthority;
  private CredentialGroup mockCredGroup;
  private SessionView mockView;
  private SessionManagerInterfaceBase mockSessionManager;

  private AuthnMechanism kerberosMechanism;
  private AuthnMechanism otherMechanism;
  private SecurityManagerConfig config;
  private AuthnSession session;
  private KerberosCredentialsGatherer testGatherer;
  private static final String CG_NAME = "group1";

  public KerberosCredentialsGathererTest()
      throws IOException, ServletException {
    integration = MockIntegration.make();
  }

  @Override
  protected void setUp() throws Exception {
    super.setUp();

    // Set up testing AuthnSession.
    kerberosMechanism = AuthnMechKerberos.make("mech1");
    otherMechanism = AuthnMechNtlm.make("mech2", SAMPLE_URL);
    config
        = makeConfig(
            Lists.newArrayList(
                CredentialGroup.builder(CG_NAME, "group1 display", true, true, false)
                .addMechanism(kerberosMechanism)
                .addMechanism(otherMechanism)
                .build()));
    session = AuthnSession.getInstance(config);

    control = EasyMock.createControl();
    mockElement = control.createMock(CredentialsGathererElement.class);
    mockView = control.createMock(SessionView.class);
    mockCredGroup = control.createMock(CredentialGroup.class);
    EasyMock.expect(mockView.getRequestId()).andReturn("MOCK_REQUEST_ID").anyTimes();
    mockAuthority = control.createMock(AuthnAuthority.class);

    // Set up mock session manager.
    mockSessionManager = control.createMock(SessionManagerInterfaceBase.class);
    SessionUtil.setGsaSessionManager(mockSessionManager);

    // Set up test kerberos credential gatherer.
    testGatherer = ConfigSingleton.getInstance(KerberosCredentialsGatherer.class);
    testGatherer.clearDomain();
  }

  public void testWillHandleSuccess() {
    // Handle the right setup.
    EasyMock.expect(mockSessionManager.getKrb5ServerNameIfEnabled())
        .andReturn(SERVER_NAME);
    control.replay();

    assertTrue(testGatherer.willHandle(session.getView(kerberosMechanism)));
    control.verify();
  }

  public void testWillHandleWrongMechanism() {
    // Handle only Kerberos mechanism.
    assertFalse(testGatherer.willHandle(session.getView(otherMechanism)));
  }

  public void testWillHandleNotConfigured() {
    // Don't handle if kerberos is disabled.
    EasyMock.expect(mockSessionManager.getKrb5ServerNameIfEnabled())
        .andReturn(null);
    control.replay();

    assertFalse(testGatherer.willHandle(session.getView(kerberosMechanism)));
    control.verify();
  }

  public void testStartGatheringSuccess() throws IOException {
    testGatherer.setDomain(REALM_NAME);

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    EasyMock.expect(mockView.getUserAgentCookie("GSA_LOGOUT_COOKIE"))
        .andReturn(null);
    EasyMock.expect(mockView.getAuthnEntryUrl())
        .andReturn(getSamlAuthnUrl());
    expectLogMessage(mockView, "Querying Kerberos credentials for realm %s",
            Stringify.object(REALM_NAME));
    control.replay();

    testGatherer.startGathering(mockElement, request, response);
    assertThat(response.getHeaders("WWW-Authenticate")).containsExactly("Negotiate").inOrder();
    assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
    control.verify();
  }

  public void testStartGatheringResend() throws IOException {
    testGatherer.setDomain(REALM_NAME);

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    request.addHeader("Authorization", "dummy");

    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    EasyMock.expect(mockView.getUserAgentCookie("GSA_LOGOUT_COOKIE"))
        .andReturn(null);
    EasyMock.expect(mockView.getAuthnEntryUrl())
        .andReturn(getSamlAuthnUrl());
    expectLogMessage(mockView, "Querying Kerberos credentials for realm %s",
            Stringify.object(REALM_NAME));
    control.replay();

    testGatherer.startGathering(mockElement, request, response);
    assertThat(response.getHeaders("WWW-Authenticate")).containsExactly("Negotiate").inOrder();
    assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
    control.verify();
  }

  public void testStartGatheringWithLogoutCookie() throws IOException {
    testGatherer.setDomain(REALM_NAME);

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    request.addHeader("Authorization", "dummy");
    GCookie logoutCookie = GCookie.make("GSA_LOGOUT_COOKIE", "foo");

    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    EasyMock.expect(mockView.getUserAgentCookie("GSA_LOGOUT_COOKIE"))
        .andReturn(logoutCookie);
    EasyMock.expect(mockView.getAuthnEntryUrl())
        .andReturn(getSamlAuthnUrl());
    expectLogMessage(mockView, "Got logout cookie.");
    expectLogMessage(mockView, "Querying Kerberos credentials for realm %s",
        Stringify.object(REALM_NAME));
    control.replay();

    CookieStore store = GCookie.makeStore();
    store.add(logoutCookie);
    testGatherer.startGathering(mockElement, request, response);
    List<String> headers = Lists.newArrayList();
    for (Object header : response.getHeaders(HttpUtil.HTTP_HEADER_SET_COOKIE)) {
      headers.add(String.class.cast(header));
    }
    GCookie.parseResponseHeaders(headers, HttpUtil.getRequestUri(request, false),
        store, SessionUtil.getLogDecorator(session.getSessionId()));
    GCookie cookie = store.get("GSA_LOGOUT_COOKIE");
    assertNull(cookie);
    assertThat(response.getHeaders("WWW-Authenticate")).containsExactly("Negotiate").inOrder();
    assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
    control.verify();
  }

  public void testContinueGatheringSuccess() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    request.addHeader("Authorization", "Negotiate " + DUMMY_RESPONSE);

    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    EasyMock.expect(mockView.getAuthority())
        .andReturn(mockAuthority);
    EasyMock.expect(mockView.getCredentialGroup())
        .andReturn(mockCredGroup);
    EasyMock.expect(mockCredGroup.getName())
        .andReturn(CG_NAME);
    EasyMock.expect(mockView.getSessionId())
        .andReturn(SESSION_ID);

    long nowSeconds = (DateTimeUtils.currentTimeMillis() + 500) / 1000;
    long expirationTimeSeconds = nowSeconds + 600L;
    long expirationTimeMillis = expirationTimeSeconds * 1000L;
    EasyMock.expect(mockSessionManager.storeKrb5Identity(SESSION_ID, DUMMY_RESPONSE))
        .andReturn(new KerberosId(USER_AND_REALM, expirationTimeSeconds));
    expectLogMessage(mockView, "Identity <%s> established using Kerberos.", USER_AND_REALM);
    mockSessionManager.setValue(SESSION_ID, "AuthN-Mech-BASIC_AUTH_USER_DOMAIN", REALM_NAME);
    expectLogMessage(mockView, "Kerberos id %s expiration %s",
        USER_AND_REALM,
        ISO8601_FORMAT.print(expirationTimeMillis));

    mockElement.addSessionState(
        AuthnSessionState.of(mockAuthority,
            Verification.verified(expirationTimeMillis,
                AuthnPrincipal.make(USER_NAME, CG_NAME, REALM_NAME))));
    control.replay();

    assertFalse(testGatherer.continueGathering(mockElement, request, response));
    control.verify();
  }

  public void testContinueGatheringNoAuthHeader() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    EasyMock.expect(mockView.getCredentialGroup())
        .andReturn(mockCredGroup);
    EasyMock.expect(mockCredGroup.getName())
        .andReturn(CG_NAME);
    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    mockElement.addSessionState(AuthnSessionState.empty());
    control.replay();

    assertFalse(testGatherer.continueGathering(mockElement, request, response));
    control.verify();
  }

  public void testContinueGatheringErrorAuthHeader() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    request.addHeader("Authorization", "junk " + DUMMY_RESPONSE);

    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    EasyMock.expect(mockView.getCredentialGroup())
        .andReturn(mockCredGroup);
    EasyMock.expect(mockCredGroup.getName())
        .andReturn(CG_NAME);
    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    mockElement.addSessionState(AuthnSessionState.empty());
    control.replay();

    assertFalse(testGatherer.continueGathering(mockElement, request, response));
    control.verify();
  }

  public void testContinueGatheringFailedKerberosVerification() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    request.addHeader("Authorization", "Negotiate " + DUMMY_RESPONSE);

    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    EasyMock.expect(mockView.getAuthority())
        .andReturn(mockAuthority);
    EasyMock.expect(mockView.getCredentialGroup())
        .andReturn(mockCredGroup);
    EasyMock.expect(mockCredGroup.getName())
        .andReturn(CG_NAME);
    EasyMock.expect(mockView.getSessionId())
        .andReturn(SESSION_ID);

    expectLogMessage(mockView, "Failed to get identity from Kerberos.");
    EasyMock.expect(mockSessionManager.storeKrb5Identity(SESSION_ID, DUMMY_RESPONSE))
        .andReturn(null);
    mockElement.addSessionState(AuthnSessionState.of(mockAuthority, Verification.refuted()));
    control.replay();

    assertFalse(testGatherer.continueGathering(mockElement, request, response));
    control.verify();
  }

  public void testContinueGatheringMalFormedKerberosVerification() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    request.addHeader("Authorization", "Negotiate " + DUMMY_RESPONSE);

    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    EasyMock.expect(mockView.getCredentialGroup())
        .andReturn(mockCredGroup);
    EasyMock.expect(mockCredGroup.getName())
        .andReturn(CG_NAME);
    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    
    EasyMock.expect(mockView.getSessionId())
        .andReturn(SESSION_ID);

    expectLogMessage(mockView, "No Kerberos domain found.");
    EasyMock.expect(mockSessionManager.storeKrb5Identity(SESSION_ID, DUMMY_RESPONSE))
        .andReturn(new KerberosId("junk", 0L));
    mockElement.addSessionState(AuthnSessionState.empty());
    control.replay();

    assertFalse(testGatherer.continueGathering(mockElement, request, response));
    control.verify();
  }

  private void expectLogMessage(SessionView mockView, String format, Object... args) {
    EasyMock.expect(mockView.logMessage(format, args))
        .andReturn(String.format(format, args));
  }

  private URL getSamlAuthnUrl()
      throws IOException {
    return new URL(MockIntegration.getSamlAuthnEndpoint(integration.getGsaHost()).getLocation());
  }
}
