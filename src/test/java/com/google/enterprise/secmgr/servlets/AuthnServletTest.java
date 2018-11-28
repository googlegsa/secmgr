/*
 * Copyright 2013 Google Inc.
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
package com.google.enterprise.secmgr.servlets;

import static com.google.enterprise.secmgr.testing.ServletTestUtil.generatePostContent;
import static com.google.enterprise.secmgr.testing.ServletTestUtil.makeMockHttpPost;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import com.google.enterprise.secmgr.authncontroller.ExportedState;
import com.google.enterprise.secmgr.authncontroller.ExportedState.Credentials;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.AuthnMechBasic;
import com.google.enterprise.secmgr.config.AuthnMechForm;
import com.google.enterprise.secmgr.config.AuthnMechGroups;
import com.google.enterprise.secmgr.config.AuthnMechPreauthenticated;
import com.google.enterprise.secmgr.config.AuthnMechSampleUrl;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigParams;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.ParamName;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.http.HttpExchange;
import com.google.enterprise.secmgr.mock.MockBasicAuthServer;
import com.google.enterprise.secmgr.mock.MockContentServer;
import com.google.enterprise.secmgr.mock.MockFormAuthServer;
import com.google.enterprise.secmgr.mock.MockIntegration;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.enterprise.sessionmanager.SessionManagerInterfaceBase;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import org.easymock.EasyMock;
import org.easymock.IMocksControl;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Unit tests for {@link AuthnServlet}.
 */
public class AuthnServletTest extends SecurityManagerTestCase {
  private static final String USER1_BASIC = "Basic dXNlcjE6dGVzdDE=";  // user1:test1
  private static final String UNTRUSTED_BASIC = "Basic am9lOnBsdW1iZXI=";  // joe:plumber
  private static final String INVALID_BASIC = "Basic dXNlcjM6dGVzdDM=";  // user3:test3
  private static final String APP_SESSION_ID = "app12345678901234567";
  private static final String USER_SESSION_ID = "user12345678901234567";

  private final AuthnSessionManager sessionManager;
  private final MockIntegration integration;
  private final URI authnServletUri;
  private final AuthnServlet authnServlet;
  private final MockHttpServletRequest mockRequest;
  private final AuthnMechanism preAuthMech;
  private final AuthnMechanism preAuthMech2;
  private final AuthnMechanism basicMech;
  private final AuthnMechanism formMech;
  private final AuthnMechanism sampleMech;
  private final String basicSampleUrl;
  private final String formSampleUrl;
  private final GCookie formCookie;
  private SessionManagerInterfaceBase gsaSessionManager;
  private IMocksControl control;

  public AuthnServletTest() throws IOException, ServletException {
    sessionManager = ConfigSingleton.getInstance(AuthnSessionManager.class);

    integration = MockIntegration.make();
    URL url = new URL(MockIntegration.getAuthnServletUrl(integration.getGsaHost()));
    mockRequest = makeMockHttpPost(null, url.toString());

    authnServletUri = URI.create(MockIntegration.getAuthnServletUrl(integration.getGsaHost()));
    authnServlet = new AuthnServlet(sessionManager);
    integration.getHttpTransport().registerServlet(
        MockIntegration.getAuthnServletUrl(integration.getGsaHost()), authnServlet);

    MockBasicAuthServer server1 = new MockBasicAuthServer.Server1("http://gsa.google.com");
    integration.addMockServer(server1);
    basicSampleUrl = server1.getSampleUrl();

    MockFormAuthServer server2 = new MockFormAuthServer.Form1("http://gsa2.google.com");
    integration.addMockServer(server2);
    formSampleUrl = server2.getSampleUrl();
    formCookie = server2.makeCookie(server2.getCookieName(),
        MockContentServer.COOKIE_VALUES.CRACK_CS_GET.toString());

    preAuthMech = AuthnMechPreauthenticated.make("trustMech");
    preAuthMech2 = AuthnMechPreauthenticated.make("trustMech2");
    basicMech = AuthnMechBasic.make("basicMech", basicSampleUrl);

    formMech = AuthnMechForm.make("formMech", formSampleUrl);
    sampleMech = AuthnMechSampleUrl.make("sampleMech", formSampleUrl, null);
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();

    integration.reset();
    control = EasyMock.createControl();
    gsaSessionManager = control.createMock(SessionManagerInterfaceBase.class);
    SessionUtil.setGsaSessionManager(gsaSessionManager);
  }

  public void testDoBasic() throws IOException {
    integration.setTestName();
    EasyMock.expect(gsaSessionManager.createSession()).andStubReturn(USER_SESSION_ID);
    control.replay();

    setupConfWithTrustUser(basicMech, false);
    mockRequest.addHeader(AuthnServlet.GSA_USER_NAME, "user2");
    mockRequest.addHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, USER1_BASIC);
    successWith("user1");
  }

  public void testDoBasicWithoutUser() throws IOException {
    integration.setTestName();
    setupConfWithTrustUser(basicMech, false);
    mockRequest.addHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, USER1_BASIC);

    generatePostContent(mockRequest);

    HttpExchange ex = integration.doAuthnQuery(mockRequest, APP_SESSION_ID);
    integration.assertExchangeStatusOk(ex);
    assertNotNull("No session id in response",
        Strings.emptyToNull(ex.getResponseHeaderValue("GSA_SESSION_ID")));

    assertEquals("user1", ex.getResponseHeaderValue("GSA_APP_ID"));
    String resp = ex.getResponseEntityAsString();
    ExportedState exportedState = ExportedState.fromJsonString(resp);
    assertEquals(1, exportedState.getAllVerifiedCredentials().size());
    // return user1's session
    assertEquals(Credentials.make("user1", "", "test1", "cg1"),
        exportedState.getAllVerifiedCredentials().get(0));
  }

  public void testDoBasicWithUntrustedUser() throws IOException {
    integration.setTestName();
    setupConfWithTrustUser(basicMech, false);
    mockRequest.addHeader(AuthnServlet.GSA_USER_NAME, "user2");
    mockRequest.addHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, UNTRUSTED_BASIC);
    failure();
  }

  public void testDoBasicFail() throws IOException {
    integration.setTestName();
    setupConfWithTrustUser(basicMech, false);
    mockRequest.addHeader(AuthnServlet.GSA_USER_NAME, "user2");
    mockRequest.addHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, INVALID_BASIC);
    failure();
  }

  public void testDoBasicMultipleCGSuccess() throws IOException {
    integration.setTestName();
    EasyMock.expect(gsaSessionManager.createSession()).andStubReturn(USER_SESSION_ID);
    control.replay();

    setupConfWithTrustUser(basicMech, false);
    mockRequest.addHeader(AuthnServlet.GSA_USER_NAME, "user2");
    mockRequest.addHeader(AuthnServlet.GSA_PASSWORD, "pwd2");
    mockRequest.addHeader(AuthnServlet.GSA_CREDENTIAL_GROUP, "cg1");
    mockRequest.addHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, USER1_BASIC);
    successInMultipleCG("user1");
  }

  public void testDoBasicMultipleCGFail() throws IOException {
    integration.setTestName();
    EasyMock.expect(gsaSessionManager.createSession()).andStubReturn(USER_SESSION_ID);
    control.replay();

    setupConfWithTrustUser(basicMech, false);
    mockRequest.addHeader(AuthnServlet.GSA_USER_NAME, "user2");
    mockRequest.addHeader(AuthnServlet.GSA_PASSWORD, "pwd2");
    mockRequest.addHeader(AuthnServlet.GSA_CREDENTIAL_GROUP, "notExist");
    mockRequest.addHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, USER1_BASIC);
    failure();
  }

  public void testLightWeightBasic() throws IOException {
    integration.setTestName();
    // No preAuthenticated mechanism.
    setupConfWithoutTrustUser(basicMech);

    mockRequest.addHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, UNTRUSTED_BASIC);

    // return the session for the basic credential.
    successFor("joe", "plumber");
  }

  public void testLightWeightBasicOtherUser(boolean withSessionCookie) throws IOException {
    integration.setTestName();
    // No preAuthenticated mechanism.
    setupConfWithoutTrustUser(basicMech);

    mockRequest.addHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, USER1_BASIC);
    mockRequest.addHeader(AuthnServlet.GSA_USER_NAME, "user2");
    // return the session for the basic credential. user2 ignored
    failure();
  }

  public void testLightWeightBasicFail() throws IOException {
    integration.setTestName();
    // No preAuthenticated mechanism.
    setupConfWithoutTrustUser(basicMech);

    mockRequest.addHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, INVALID_BASIC);
    failure();
  }

  public void testFormsAuth() throws IOException {
    integration.setTestName();
    runFormsAuthTest(formMech);
  }

  public void testSampleUrlAuth() throws IOException {
    integration.setTestName();
    runFormsAuthTest(sampleMech);
  }

  public void testFormsAuthFail() throws IOException {
    integration.setTestName();
    runFormsAuthTestFail(formMech);
  }

  public void testSampleUrlAuthFail() throws IOException {
    integration.setTestName();
    runFormsAuthTestFail(sampleMech);
  }

  public void testFormsAuthMultipleCG() throws IOException {
    integration.setTestName();
    runFormsAuthMultipleCG(formMech);
  }

  public void testSampleUrlAuthMultipleCG() throws IOException {
    integration.setTestName();
    runFormsAuthMultipleCG(sampleMech);
  }

  /**
   * Test case for bug 12450218.
   *
   * Ensures that no race condition occurs when concurrent authn requests
   * come in for the same end user.
   *
   * This test is not a definitive proof that the code works, but it used
   * to consistently fail without the synchronization block that's currently
   * in place. That the test now passes rather than consistently fail is a
   * good enough first-pass for now.
   */
  public void testConcurrentForSameUser() throws Exception {
    ThreadPoolExecutor testExecutor = new ThreadPoolExecutor(10, 10, 0L, TimeUnit.MILLISECONDS,
        new LinkedBlockingQueue<Runnable>());
    // No preAuthenticated mechanism.
    integration.setTestName();
    EasyMock.expect(gsaSessionManager.createSession()).andStubReturn(USER_SESSION_ID);
    control.replay();

    setupConfWithTrustUser(basicMech, false);

    int numTimes = 10;
    final SynchronizedCounter doneThreads = new SynchronizedCounter();
    final SynchronizedCounter successThreads = new SynchronizedCounter();

    for (int i = 0; i < numTimes; i++) {
      Thread t = new Thread(new Runnable() {
        @Override
        public void run() {
          try {
            URL url = new URL(MockIntegration.getAuthnServletUrl(integration.getGsaHost()));
            MockHttpServletRequest request = makeMockHttpPost(null, url.toString());
            request.addHeader(AuthnServlet.GSA_USER_NAME, "user2");
            request.addHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, USER1_BASIC);
            generatePostContent(request);
            HttpExchange ex = integration.doAuthnQuery(request, APP_SESSION_ID, false);
            integration.assertExchangeStatusOk(ex);
            assertEquals("user1", ex.getResponseHeaderValue("GSA_APP_ID"));
            String resp = ex.getResponseEntityAsString();
            ExportedState exportedState = ExportedState.fromJsonString(resp);
            assertEquals(1, exportedState.getAllVerifiedCredentials().size());
            assertEquals(Credentials.make("user2", null, null, "Default"),
              exportedState.getAllVerifiedCredentials().get(0));
            successThreads.increment();
          } catch (IOException e) {
            // let this fall through
          } finally {
            doneThreads.increment();
          }
        }
      });
      testExecutor.execute(t);
    }
    testExecutor.shutdown();
    if (!testExecutor.awaitTermination(1, TimeUnit.SECONDS)) {
      fail("Failed with time out");
    }
    assertEquals(numTimes, successThreads.get());
  }

  private void setupConfWithTrustUser(AuthnMechanism mech, boolean oneCG) throws IOException {
    setupConf(mech, true, oneCG);
  }

  private void setupConfWithoutTrustUser(AuthnMechanism mech) throws IOException {
    setupConf(mech, false, true);
  }

  private void setupConf(AuthnMechanism mech, boolean withTrustUser, boolean oneCG)
      throws IOException {
    SecurityManagerConfig config;
    if (withTrustUser) {
      if (oneCG) {
        config = makeConfig(
            ImmutableList.of(
                CredentialGroup.builder(CredentialGroup.DEFAULT_NAME,
                                        CredentialGroup.DEFAULT_NAME,
                                        false, false, true)
                               .addMechanism(mech)
                               .addMechanism(preAuthMech)
                               .build()));
      } else {
        config = makeConfig(
            ImmutableList.of(
                CredentialGroup.builder("cg1", "cg1", false, false, true)
                               .addMechanism(mech)
                               .addMechanism(preAuthMech)
                               .build(),
                CredentialGroup.builder(CredentialGroup.DEFAULT_NAME,
                                        CredentialGroup.DEFAULT_NAME,
                                        false, false, true)
                               .addMechanism(preAuthMech2)
                               .addMechanism(AuthnMechGroups.make("mechGroups1"))
                               .build()));
      }
    } else {
      config = makeConfig(
          ImmutableList.of(
              CredentialGroup.builder(CredentialGroup.DEFAULT_NAME,
                                      CredentialGroup.DEFAULT_NAME,
                                      false, false, true)
                             .addMechanism(mech)
                             .addMechanism(AuthnMechGroups.make("mechGroups"))
                             .build()));
    }
    ConfigParams.Builder builder = ConfigParams.builder();
    ConfigParams oldParams = config.getParams();
    for (ParamName paramName : ConfigParams.keySet()) {
      if (paramName == ParamName.TRUST_FILENAME) {
        if (withTrustUser) {
          builder.put(paramName, "trust.enterprise");
        } else {
          builder.put(paramName, "notrust.enterprise");
        }
      } else {
        builder.put(paramName, oldParams.get(paramName));
      }
    }
    config.setParams(builder.build());
    ConfigSingleton.setConfig(config);

    GCookie sessionCookie = GCookie.make(SessionUtil.GSA_SESSION_ID_COOKIE_NAME, APP_SESSION_ID);
    mockRequest.setCookies(new Cookie[] { sessionCookie.toCookie() });
    mockRequest.addHeader(HttpUtil.HTTP_HEADER_COOKIE, sessionCookie.requestHeaderString(true));
  }

  private void runFormsAuthTest(AuthnMechanism mech) throws IOException {
    EasyMock.expect(gsaSessionManager.createSession()).andStubReturn(USER_SESSION_ID);
    control.replay();

    setupConfWithTrustUser(mech, true);
    mockRequest.addHeader(AuthnServlet.GSA_USER_NAME, "user2");
    mockRequest.setCookies(new Cookie[] { formCookie.toCookie() });
    mockRequest.addHeader(HttpUtil.HTTP_HEADER_COOKIE, formCookie.requestHeaderString(true));
    successWith("CRACK_CS_GET");
  }

  private void runFormsAuthTestFail(AuthnMechanism mech) throws IOException {
    EasyMock.expect(gsaSessionManager.createSession()).andStubReturn(USER_SESSION_ID);
    control.replay();

    setupConfWithTrustUser(mech, true);
    mockRequest.addHeader(AuthnServlet.GSA_USER_NAME, "user2");
    failure();
  }

  private void runFormsAuthMultipleCG(AuthnMechanism mech) throws IOException {
    EasyMock.expect(gsaSessionManager.createSession()).andStubReturn(USER_SESSION_ID);
    control.replay();

    SecurityManagerConfig config = makeConfig(
        ImmutableList.of(
            CredentialGroup.builder("cg1", "cg1", false, false, true)
                           .addMechanism(preAuthMech)
                           .addMechanism(AuthnMechGroups.make("mechGroups"))
                           .build(),
            CredentialGroup.builder(CredentialGroup.DEFAULT_NAME,
                                    CredentialGroup.DEFAULT_NAME,
                                    false, false, true)
                           .addMechanism(mech)
                           .addMechanism(preAuthMech2)
                           .build()));
    ConfigParams.Builder builder = ConfigParams.builder();
    ConfigParams oldParams = config.getParams();
    for (ParamName paramName : ConfigParams.keySet()) {
      if (paramName == ParamName.TRUST_FILENAME) {
        builder.put(paramName, "trust.enterprise");
      } else {
        builder.put(paramName, oldParams.get(paramName));
      }
    }
    config.setParams(builder.build());
    ConfigSingleton.setConfig(config);

    GCookie sessionCookie = GCookie.make(SessionUtil.GSA_SESSION_ID_COOKIE_NAME, APP_SESSION_ID);
    mockRequest.setCookies(new Cookie[] { sessionCookie.toCookie() });
    mockRequest.addHeader(HttpUtil.HTTP_HEADER_COOKIE, sessionCookie.requestHeaderString(true));

    mockRequest.addHeader(AuthnServlet.GSA_USER_NAME, "user2");
    mockRequest.addHeader(AuthnServlet.GSA_PASSWORD, "pwd2");
    mockRequest.addHeader(AuthnServlet.GSA_CREDENTIAL_GROUP, "cg1");
    mockRequest.setCookies(new Cookie[] { formCookie.toCookie() });
    mockRequest.addHeader(HttpUtil.HTTP_HEADER_COOKIE, formCookie.requestHeaderString(true));
    successInMultipleCG("CRACK_CS_GET");
  }

  private void failure() throws IOException {
    generatePostContent(mockRequest);

    HttpExchange ex = integration.doAuthnQuery(mockRequest, APP_SESSION_ID);
    integration.assertServerErrorResult(ex);
  }

  private void successWith(String user) throws IOException {
    generatePostContent(mockRequest);

    HttpExchange ex = integration.doAuthnQuery(mockRequest, APP_SESSION_ID);
    integration.assertExchangeStatusOk(ex);
    assertNotNull("No session id in response",
        Strings.emptyToNull(ex.getResponseHeaderValue("GSA_SESSION_ID")));
    assertEquals(user, ex.getResponseHeaderValue("GSA_APP_ID"));
    String resp = ex.getResponseEntityAsString();
    ExportedState exportedState = ExportedState.fromJsonString(resp);
    assertEquals(1, exportedState.getAllVerifiedCredentials().size());
    assertEquals(Credentials.make("user2", null, null, "Default"),
        exportedState.getAllVerifiedCredentials().get(0));
    control.verify();
  }

  private void successInMultipleCG(String user) throws IOException {
    generatePostContent(mockRequest);

    HttpExchange ex = integration.doAuthnQuery(mockRequest, APP_SESSION_ID);
    integration.assertExchangeStatusOk(ex);
    assertNotNull("No session id in response",
        Strings.emptyToNull(ex.getResponseHeaderValue("GSA_SESSION_ID")));
    assertEquals(user, ex.getResponseHeaderValue("GSA_APP_ID"));
    String resp = ex.getResponseEntityAsString();
    ExportedState exportedState = ExportedState.fromJsonString(resp);
    assertEquals(1, exportedState.getAllVerifiedCredentials().size());
    assertEquals(Credentials.make("user2", null, "pwd2", "cg1"),
        exportedState.getAllVerifiedCredentials().get(0));
    control.verify();
  }

  private void successFor(String user, String password) throws IOException {
    mockRequest.addHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, USER1_BASIC);

    generatePostContent(mockRequest);

    HttpExchange ex = integration.doAuthnQuery(mockRequest, APP_SESSION_ID);
    integration.assertExchangeStatusOk(ex);
    assertNotNull("No session id in response",
        Strings.emptyToNull(ex.getResponseHeaderValue("GSA_SESSION_ID")));
    assertEquals(user, ex.getResponseHeaderValue("GSA_APP_ID"));
    String resp = ex.getResponseEntityAsString();
    ExportedState exportedState = ExportedState.fromJsonString(resp);
    assertEquals(1, exportedState.getAllVerifiedCredentials().size());
    assertEquals(Credentials.make(user, "", password, "Default"),
        exportedState.getAllVerifiedCredentials().get(0));
  }

  /**
   * Internal mini-class that wraps a simple thread-safe counter.
   */
  private static class SynchronizedCounter {
    private volatile int c = 0;

    public synchronized void increment() {
      c++;
      notifyAll();
    }

    public synchronized void reset() {
      c = 0;
      notifyAll();
    }

    public synchronized int get() {
      return c;
    }
  }
}
