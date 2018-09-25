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

package com.google.enterprise.secmgr.modules;

import static org.easymock.EasyMock.replay;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.CookieStore;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.http.KerberosHttpAuthenticator;
import com.google.enterprise.secmgr.mock.MockBasicAuthServer;
import com.google.enterprise.secmgr.mock.MockFormAuthServer;
import com.google.enterprise.secmgr.mock.MockIntegration;
import com.google.enterprise.secmgr.mock.MockKerberosAuthServer;
import com.google.enterprise.secmgr.mock.MockNtlmAuthServer;
import com.google.enterprise.secmgr.testing.AuthorizationTestUtils;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.enterprise.sessionmanager.KeyMaterial;
import com.google.enterprise.sessionmanager.SessionManagerInterfaceBase;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.util.List;
import javax.servlet.ServletException;
import org.easymock.EasyMock;
import org.easymock.Mock;

/**
 * Tests for the {@link HttpRequestModule} class.
 */
public class HttpRequestModuleTest extends SecurityManagerTestCase {

  private static final String BASIC_CONTEXT_URL = "http://localhost:8973/basic";
  private static final String NTLM_CONTEXT_URL = "http://localhost:8973/ntlm";
  private static final String KERBEROS_CONTEXT_URL = "http://localhost:8973/kerberos";
  private static final String SESSION_ID = "121";
  private static final String REQUEST_ID = "343";
  private static final String GOOD_TICKET = "good";
  private static final String BAD_TICKET = "bad";

  private final MockIntegration integration;
  private final String basicSampleUrl;
  private final String ntlmSampleUrl;
  private final String kerberosSampleUrl;
  private final HttpRequestModule module;
  @Mock private SessionView view;
  @Mock private AuthnAuthority authority;
  @Mock private SessionManagerInterfaceBase sessionManager;
  @Mock private KeyMaterial token;
  MockBasicAuthServer basicServer;

  public HttpRequestModuleTest()
      throws IOException, ServletException {
    integration = MockIntegration.make();
    basicServer = new MockBasicAuthServer.Server1(BASIC_CONTEXT_URL);
    integration.addMockServer(basicServer);
    basicSampleUrl = basicServer.getSampleUrl();

    MockNtlmAuthServer ntlmServer
        = new MockNtlmAuthServer(NTLM_CONTEXT_URL, ImmutableMap.of("joe", "plumber"));
    integration.addMockServer(ntlmServer);
    ntlmSampleUrl = ntlmServer.getSampleUrl();

    MockKerberosAuthServer kerberosServer
        = new MockKerberosAuthServer(KERBEROS_CONTEXT_URL, ImmutableList.of(GOOD_TICKET));
    integration.addMockServer(kerberosServer);
    kerberosSampleUrl = kerberosServer.getSampleUrl();

    module = ConfigSingleton.getInstance(HttpRequestModule.class);
  }

  @Override
  protected void setUp()
      throws Exception {
    super.setUp();
    integration.reset();
    KerberosHttpAuthenticator.setTestSessionManager(sessionManager);
  }

  public void testBasicHttpAuthorizeSuccess()
      throws MalformedURLException {
    assertEquals(AuthzStatus.PERMIT, tryAuthorize("joe", "plumber", basicSampleUrl));
  }

  public void testBasicHttpAuthorizeFail()
      throws MalformedURLException {
    assertEquals(AuthzStatus.DENY, tryAuthorize("joe", "biden", basicSampleUrl));
  }

  public void testNtlmHttpAuthorizeSuccess()
      throws MalformedURLException {
    EasyMock.expect(sessionManager.getKrb5ServerNameIfEnabled()).andStubReturn(null);
    assertEquals(AuthzStatus.PERMIT, tryAuthorize("joe", "plumber", ntlmSampleUrl));
  }

  public void testNtlmHttpAuthorizeFail()
      throws MalformedURLException {
    EasyMock.expect(sessionManager.getKrb5ServerNameIfEnabled()).andStubReturn(null);
    assertEquals(AuthzStatus.DENY, tryAuthorize("joe", "biden", ntlmSampleUrl));
  }

  public void testKerberosHttpAuthorizeSuccess()
      throws MalformedURLException {
    EasyMock.expect(sessionManager.getKrb5ServerNameIfEnabled()).andStubReturn("x@y");
    EasyMock.expect(sessionManager.sessionExists(SESSION_ID)).andStubReturn(true);
    EasyMock.expect(sessionManager.getKrb5TokenForServer(SESSION_ID, "HTTP/localhost@y"))
        .andReturn(token);
    EasyMock.expect(token.spnegoBlob()).andStubReturn(GOOD_TICKET);
    EasyMock.replay(sessionManager, token);
    assertEquals(AuthzStatus.PERMIT, tryAuthorize(null, null, kerberosSampleUrl));
  }

  public void testKerberosHttpAuthorizeFail()
      throws MalformedURLException {
    EasyMock.expect(sessionManager.getKrb5ServerNameIfEnabled()).andStubReturn("x@y");
    EasyMock.expect(sessionManager.sessionExists(SESSION_ID)).andStubReturn(true);
    EasyMock.expect(sessionManager.getKrb5TokenForServer(SESSION_ID, "HTTP/localhost@y"))
        .andReturn(token);
    EasyMock.expect(token.spnegoBlob()).andStubReturn(BAD_TICKET);
    assertEquals(AuthzStatus.DENY, tryAuthorize(null, null, kerberosSampleUrl));
  }

  public void testUrls()
      throws MalformedURLException {
    EasyMock.expect(sessionManager.getKrb5ServerNameIfEnabled()).andStubReturn(null);
    AuthzResult result = tryAuthorize("joe", "plumber",
        ImmutableList.of(basicSampleUrl, ntlmSampleUrl));
    assertEquals(AuthzStatus.PERMIT, result.get(basicSampleUrl));
    assertEquals(AuthzStatus.PERMIT, result.get(ntlmSampleUrl));
  }

  public void testFormAuthorizeRedirectToForm()
      throws MalformedURLException {
    assertEquals(AuthzStatus.DENY,
        tryAuthorize(null, null, integration.getMockFormAuthServer().getSampleUrl()));
  }

  public void testSocketErrorOnOneUrlShouldReturnIndeterminateOnlyForFailedUrl()
      throws MalformedURLException {
    // b/30796660
    EasyMock.expect(sessionManager.getKrb5ServerNameIfEnabled()).andStubReturn(null);
    MockFormAuthServer authServer = integration.getMockFormAuthServer();
    authServer.setExceptionToBeThrownOnNextRequest(
        new SocketException("Connection reset by peer."));
    String formAuthUrl = integration.getMockFormAuthServer().getSampleUrl();
    EasyMock.expect(view.logMessage(EasyMock.eq("%s"),
        EasyMock.eq("Connection reset by peer."))).andReturn("");
    AuthzResult result = tryAuthorize("joe", "plumber",
        ImmutableList.of(basicSampleUrl, formAuthUrl, ntlmSampleUrl));
    assertEquals(AuthzStatus.PERMIT, result.get(basicSampleUrl));
    assertEquals(AuthzStatus.INDETERMINATE, result.get(formAuthUrl));
    assertEquals(AuthzStatus.PERMIT, result.get(ntlmSampleUrl));
  }

  public void testFormAuthorizeDirectToForm()
      throws MalformedURLException {
    assertEquals(AuthzStatus.PERMIT,
        tryAuthorize(null, null, integration.getMockFormAuthServer().getLoginUrl()));
  }

  private AuthzResult tryAuthorize(String username, String password, List<String> urlStrings)
      throws MalformedURLException {
    EasyMock.expect(view.getDomain()).andStubReturn("dummy");
    EasyMock.expect(view.getUsername()).andStubReturn(username);
    EasyMock.expect(view.getPassword()).andStubReturn(password);
    EasyMock.expect(view.getSessionId()).andStubReturn(SESSION_ID);
    EasyMock.expect(view.getRequestId()).andStubReturn(REQUEST_ID);
    EasyMock.expect(view.getAuthority()).andStubReturn(authority);
    EasyMock.expect(view.getLogDecorator()).andStubReturn(SessionUtil.getLogDecorator());
    EasyMock.expect(view.logMessage(
        EasyMock.eq("HttpRequest url: %s user: %s HTTP status: %d"),
        EasyMock.anyObject(String.class),
        EasyMock.anyObject(String.class),
        EasyMock.anyInt()))
        .andStubReturn("HttpRequest url: %s user: %s HTTP status: %d");
    CookieStore cookies = GCookie.makeStore();
    //cookies.add(new Cookie(KerberosHttpAuthenticator.GSA_SESSION_ID_COOKIE_NAME, SESSION_ID));
    EasyMock.expect(view.getUserAgentCookies()).andStubReturn(cookies);
    ImmutableSet<GCookie> authorityCookies = ImmutableSet.of(GCookie.make("cookie1", ""));
    EasyMock.expect(view.getAuthorityCookies()).andStubReturn(authorityCookies);
    replay(view);
    return module.authorize(Resource.urlsToResourcesNoAcls(urlStrings),
        view, AuthorizationTestUtils.DUMMY_RULE);
  }

  private AuthzStatus tryAuthorize(String username, String password, String urlString)
      throws MalformedURLException {
    return tryAuthorize(username, password, ImmutableList.of(urlString)).get(urlString);
  }
}
