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

package com.google.enterprise.secmgr.mock;

import static com.google.enterprise.secmgr.testing.ExchangeLog.logForbidden;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logGet;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logOk;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logPost;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logRedirect;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logResponse;
import static com.google.enterprise.secmgr.testing.ExchangeLog.logSequence;
import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static javax.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static javax.servlet.http.HttpServletResponse.SC_PARTIAL_CONTENT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.google.common.base.Preconditions;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManagerImpl;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.authzcontroller.AuthorizationController;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.CookieStore;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HtmlParser;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.docfetchercontroller.DocumentFetcherController;
import com.google.enterprise.secmgr.http.HttpClientUtil;
import com.google.enterprise.secmgr.http.HttpExchange;
import com.google.enterprise.secmgr.mock.MockContentServer.COOKIE_VALUES;
import com.google.enterprise.secmgr.modules.SamlAuthzClient;
import com.google.enterprise.secmgr.saml.Group;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.saml.SecmgrCredential;
import com.google.enterprise.secmgr.servlets.AuthnServlet;
import com.google.enterprise.secmgr.servlets.AuthzServlet;
import com.google.enterprise.secmgr.servlets.DocumentFetcher;
import com.google.enterprise.secmgr.servlets.SamlArtifactResolve;
import com.google.enterprise.secmgr.servlets.SamlAssertionConsumer;
import com.google.enterprise.secmgr.servlets.SamlAuthn;
import com.google.enterprise.secmgr.servlets.SamlAuthz;
import com.google.enterprise.secmgr.testing.ExchangeLog;
import com.google.enterprise.secmgr.testing.ExchangeLog.LogItem;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.enterprise.util.C;
import java.io.IOException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import junit.framework.AssertionFailedError;
import org.apache.commons.text.StringEscapeUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.PDPDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Support for implementing end-to-end integration tests of the security manager.
 *
 * Each instance of this class implements a complete security manager, with mock
 * GSA, mock user agent, and mock HTTP transport.  The test using the instance
 * need only set up the security manager configuration and the back-end content
 * servers, then start the test by initiating a GSA search from the user agent.
 */
public class MockIntegration {
  private static final Logger logger = Logger.getLogger(MockIntegration.class.getName());

  private static final String DEFAULT_GSA_HOST = "localhost";

  // Must match "common/testdata/AuthSites.json":
  private static final String FORM_CONTEXT_URL = "http://form1.example.com";

  private static final String SP_SUCCESS_TEXT = "...is what we've got";
  private static final String LOGIN_FORM_TEXT = "Google Search Appliance Universal Login Form";
  private static final String POST_BINDING_TEXT = "<body onload=\"document.forms[0].submit()\">";

  // Mock GSA servlets.
  private final MockServiceProvider mockServiceProvider;
  private final MockArtifactConsumer mockAssertionConsumer;

  // Security Manager servlets.
  private final SamlArtifactResolve samlArtifactResolver;
  private final SamlAssertionConsumer samlAssertionConsumer;
  private final SamlAuthn samlAuthn;
  private final SamlAuthz samlAuthz;
  private final AuthnServlet authnServlet;
  private final AuthzServlet authzServlet;

  // Document Fetcher servlet.
  private final DocumentFetcher documentFetcher;

  // Mock back-end servers.
  private final List<MockServer> mockServers;

  // Major internal components.
  private final AuthnController authnController;
  private final AuthnSessionManager authnSessionManager;
  private final AuthorizationController authzController;
  private final DocumentFetcherController docFetcherController;

  // Transport.
  private final MockHttpTransport transport;
  private final Map<String, URL> gsaHosts;

  // User agent.
  private final CookieStore userAgentCookies;
  private final MockHttpClient userAgent;
  private String sessionId;
  private Decorator decorator;
  private String testName;
  private int testNameCounter;
  private boolean followRedirects = true;

  private MockIntegration()
      throws IOException, ServletException {

    SamlSharedData sharedData
        = SamlSharedData.make(C.entityIdForGsa(SecurityManagerTestCase.GSA_TESTING_ISSUER),
            SamlSharedData.Role.SERVICE_PROVIDER,
            null);
    mockServiceProvider = new MockServiceProvider(sharedData);
    mockAssertionConsumer = new MockArtifactConsumer(sharedData);

    samlAuthn = ConfigSingleton.getInstance(SamlAuthn.class);
    samlArtifactResolver = ConfigSingleton.getInstance(SamlArtifactResolve.class);
    samlAssertionConsumer = ConfigSingleton.getInstance(SamlAssertionConsumer.class);
    samlAuthz = ConfigSingleton.getInstance(SamlAuthz.class);
    authnServlet = ConfigSingleton.getInstance(AuthnServlet.class);
    authzServlet = ConfigSingleton.getInstance(AuthzServlet.class);
    documentFetcher = ConfigSingleton.getInstance(DocumentFetcher.class);

    authnController = ConfigSingleton.getInstance(AuthnController.class);
    authnSessionManager = ConfigSingleton.getInstance(AuthnSessionManager.class);
    authzController = ConfigSingleton.getInstance(AuthorizationController.class);
    docFetcherController = ConfigSingleton.getInstance(DocumentFetcherController.class);

    transport = new MockHttpTransport();
    gsaHosts = Maps.newHashMap();
    addGsaHost(DEFAULT_GSA_HOST);

    mockServers = Lists.newArrayList();
    addMockServer(new MockFormAuthServer.Form1(FORM_CONTEXT_URL));

    userAgentCookies = GCookie.makeStore();
    userAgent = new MockHttpClient(transport, userAgentCookies);
    userAgent.setFillInBoilerplateHeaders(true);

    reset();
  }

  /**
   * Resets all of the mock back-end servers and the exchange log.
   * For use in the #setUp method of a test.
   */
  public void reset() {
    transport.resetServletContexts();
    transport.resetExchangeLog();
    testName = null;
    testNameCounter = 0;
    ((AuthnSessionManagerImpl) authnSessionManager).reset();
    userAgentCookies.clear();
    newSession();
    HttpClientUtil.setHttpClient(new MockHttpClient(transport));
    for (MockServer server : mockServers) {
      server.reset();
    }
  }

  /**
   * @return A new integration instance.
   */
  public static MockIntegration make()
      throws IOException, ServletException {
    return new MockIntegration();
  }

  /**
   * Sets the name of the current test.  Must be called at the beginning of the
   * test method, directly from the method.  It gets the method name by
   * searching the call stack.
   */
  public void setTestName() {
    Preconditions.checkState(this.testName == null);
    StackTraceElement st[] = Thread.currentThread().getStackTrace();
    this.testName = st[2].getMethodName();
    testNameCounter = 0;
    startTestMessage();
  }

  /**
   * @return The default GSA host name.
   */
  public String getGsaHost() {
    return DEFAULT_GSA_HOST;
  }

  /**
   * Adds an alternate host name for the mock GSA.  This is useful for testing
   * whether the security manager works properly with a different hostname.
   *
   * @param host The alternate host name.
   */
  public void addGsaHost(String host)
      throws IOException, ServletException {
    if (!gsaHosts.containsKey(host)) {
      URL searchUrl = new URL(getGsaEntityContextUrl(host) + "/mockserviceprovider");

      transport.registerEntity(getGsaEntity(host), getGsaEntityContextUrl(host));
      transport.registerServlet(searchUrl, mockServiceProvider);
      transport.registerServlet(getGsaAssertionConsumerEndpoint(host), mockAssertionConsumer);

      transport.registerEntity(getSmEntity(host), getSmEntityContextUrl(host));
      transport.registerServlet(getSamlAuthnEndpoint(host), samlAuthn);
      transport.registerServlet(getSamlArtifactResolverEndpoint(host), samlArtifactResolver);
      transport.registerServlet(getSamlAssertionConsumerEndpoint(host), samlAssertionConsumer);
      transport.registerServlet(getSamlAuthzEndpoint(host), samlAuthz);
      transport.registerServlet(getAuthnServletUrl(host), authnServlet);
      transport.registerServlet(getAuthzServletUrl(host), authzServlet);
      transport.registerServlet(getDocFetcherEndpoint(host), documentFetcher);

      gsaHosts.put(host, searchUrl);
    }
  }

  /**
   * @param host The host name to get the search URL for.
   * @return The search URL for the mock GSA, using the given host name.
   */
  public URL getGsaSearchUrl(String host) {
    URL searchUrl = gsaHosts.get(host);
    Preconditions.checkNotNull(searchUrl);
    return searchUrl;
  }

  /**
   * @return The search URL for the mock GSA, using the default host name.
   */
  public URL getGsaSearchUrl() {
    return getGsaSearchUrl(getGsaHost());
  }

  /**
   * Adds a mock back-end server to this integration.
   *
   * @param mockServer The mock back-end server to add.
   */
  public void addMockServer(MockServer mockServer)
      throws IOException, ServletException {
    if (!mockServers.contains(mockServer)) {
      mockServer.addToIntegration(this);
      mockServers.add(mockServer);
    }
  }

  /**
   * @return An immutable list of the mock servers, in the order they were
   * added.
   */
  public List<MockServer> getMockServers() {
    return ImmutableList.copyOf(mockServers);
  }

  /**
   * @return The standard mock form-auth server.
   */
  public MockFormAuthServer getMockFormAuthServer() {
    return (MockFormAuthServer) mockServers.get(0);
  }

  /**
   * @return The "entity context URL" for the mock GSA with the default host
   * name.  This is the base URL that all mock GSA URLs are descended from.
   */
  public String getGsaEntityContextUrl() {
    return getGsaEntityContextUrl(getGsaHost());
  }

  /**
   * @param host A host name for the mock GSA.
   * @return The "entity context URL" for the mock GSA with a given host name.
   * This is the base URL that all mock GSA URLs are descended from.
   */
  public static String getGsaEntityContextUrl(String host) {
    return "http://" + host + ":1234/gsa";
  }

  /**
   * @return The "entity context URL" for the Security Manager with the default
   * host name.  This is the base URL that all Security Manager URLs are
   * descended from.
   */
  public String getSmEntityContextUrl() {
    return getSmEntityContextUrl(getGsaHost());
  }

  /**
   * @param host A host name for the Security Manager.
   * @return The "entity context URL" for the Security Manager with a given host
   * name.  This is the base URL that all Security Manager URLs are descended
   * from.
   */
  public static String getSmEntityContextUrl(String host) {
    return "http://" + host + ":8973/security-manager";
  }

  /**
   * @param host A host name for the Security Manager.
   * @return The full URL to the Document Fetcher servlet.
   */
  public static String getDocFetcherEndpoint(String host) {
    return getSmEntityContextUrl(host) + "/fetchDocument";
  }

  /**
   * @param host A host name for the Security Manager.
   * @return The full URL to the authentication servlet.
   */
  public static String getAuthnServletUrl(String host) {
    return getSmEntityContextUrl(host) + "/authenticate";
  }

  /**
   * @param host A host name for the Security Manager.
   * @return The full URL to the authorization servlet.
   */
  public static String getAuthzServletUrl(String host) {
    return getSmEntityContextUrl(host) + "/authorize";
  }

  /**
   * @return The SAML Metadata Entity Descriptor for the mock GSA, using the
   * default host name.
   */
  public EntityDescriptor getGsaEntity()
      throws IOException {
    return getGsaEntity(getGsaHost());
  }

  /**
   * @return The SAML entity ID for the mock GSA.
   */
  public String getGsaEntityId()
      throws IOException {
    return getGsaEntity().getEntityID();
  }

  /**
   * @param host A host name for the mock GSA.
   * @return The SAML Metadata Entity Descriptor for the mock GSA.
   */
  public static EntityDescriptor getGsaEntity(String host)
      throws IOException {
    return Metadata.getInstanceForTest(host).getEntity(
        C.entityIdForGsa(SecurityManagerTestCase.GSA_TESTING_ISSUER));
  }

  /**
   * @param host A host name for the mock GSA.
   * @return The SAML Metadata Service Provider SSO Descriptor for the mock GSA.
   */
  public static SPSSODescriptor getGsaSpSsoDescriptor(String host)
      throws IOException {
    return getGsaEntity(host).getSPSSODescriptor(SAMLConstants.SAML20P_NS);
  }

  /**
   * @param host A host name for the mock GSA.
   * @return The SAML Metadata Assertion Consumer Endpoint for the mock GSA.
   */
  public static Endpoint getGsaAssertionConsumerEndpoint(String host)
      throws IOException {
    return getGsaSpSsoDescriptor(host).getDefaultAssertionConsumerService();
  }

  /**
   * @return The SAML Metadata Entity Descriptor for the Security Manager, using
   * the default host name.
   */
  public EntityDescriptor getSmEntity()
      throws IOException {
    return getSmEntity(getGsaHost());
  }

  /**
   * @param host A host name for the Security Manager.
   * @return The SAML Metadata Entity Descriptor for the Security Manager.
   */
  public static EntityDescriptor getSmEntity(String host)
      throws IOException {
    return Metadata.getInstanceForTest(host).getSmEntity();
  }

  /**
   * @param host A host name for the Security Manager.
   * @return The SAML Metadata Identity Provider SSO Descriptor for the Security
   * Manager.
   */
  public static IDPSSODescriptor getSmIdpSsoDescriptor(String host)
      throws IOException {
    return getSmEntity(host).getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
  }

  /**
   * @param host A host name for the Security Manager.
   * @return The SAML Metadata Service Provider SSO Descriptor for the Security
   * Manager.
   */
  public static SPSSODescriptor getSmSpSsoDescriptor(String host)
      throws IOException {
    return getSmEntity(host).getSPSSODescriptor(SAMLConstants.SAML20P_NS);
  }

  /**
   * @param host A host name for the Security Manager.
   * @return The SAML Metadata Policy Decision Point Descriptor for the Security
   * Manager.
   */
  public static PDPDescriptor getSmPdpDescriptor(String host)
      throws IOException {
    return getSmEntity(host).getPDPDescriptor(SAMLConstants.SAML20P_NS);
  }

  /**
   * @param host A host name for the Security Manager.
   * @return The SAML Metadata Authentication Service Endpoint for the Security
   * Manager.
   */
  public static Endpoint getSamlAuthnEndpoint(String host)
      throws IOException {
    return getSmIdpSsoDescriptor(host).getSingleSignOnServices().get(0);
  }

  /**
   * @param host A host name for the Security Manager.
   * @return The SAML Metadata Artifact Resolution Service Endpoint for the
   * Security Manager.
   */
  public static Endpoint getSamlArtifactResolverEndpoint(String host)
      throws IOException {
    return getSmIdpSsoDescriptor(host).getDefaultArtifactResolutionService();
  }

  /**
   * @param host A host name for the Security Manager.
   * @return The SAML Metadata Assertion Consumer Service Endpoint for the
   * Security Manager.
   */
  public static Endpoint getSamlAssertionConsumerEndpoint(String host)
      throws IOException {
    return getSmSpSsoDescriptor(host).getDefaultAssertionConsumerService();
  }

  /**
   * @param host A host name for the Security Manager.
   * @return The SAML Metadata Authorization Service Endpoint for the Security
   * Manager.
   */
  public static Endpoint getSamlAuthzEndpoint(String host)
      throws IOException {
    return getSmPdpDescriptor(host).getAuthzServices().get(0);
  }

  /**
   * @return The SAML Metadata for the default host name.
   */
  public Metadata getMetadata()
      throws IOException {
    return Metadata.getInstanceForTest(getGsaHost());
  }

  /**
   * @return The SAML Metadata Authentication Service URL for the Security
   * Manager, using the default host name.
   */
  public URL getSamlAuthnUrl()
      throws IOException {
    return new URL(getSamlAuthnEndpoint(getGsaHost()).getLocation());
  }

  /**
   * @return The SAML Metadata Assertion Consumer Service URL for the
   * Security Manager, using the default host name.
   */
  public URL getSamlAssertionConsumerUrl()
      throws IOException {
    return new URL(getSamlAssertionConsumerEndpoint(getGsaHost()).getLocation());
  }

  /**
   * @return The SAML Metadata Policy Decision Point Service URL for the
   * Security Manager, using the default host name.
   */
  public URL getSamlAuthzUrl()
      throws IOException {
    return new URL(getSamlAuthzEndpoint(getGsaHost()).getLocation());
  }

  /**
   * @return The mock GSA Service Provider servlet.
   */
  public MockServiceProvider getGsaServiceProvider() {
    return mockServiceProvider;
  }

  /**
   * @return The mock GSA Assertion Consumer servlet.
   */
  public MockArtifactConsumer getGsaAssertionConsumer() {
    return mockAssertionConsumer;
  }

  /**
   * @return The Security Manager Authentication servlet.
   */
  public SamlAuthn getSamlAuthn() {
    return samlAuthn;
  }

  /**
   * @return The Security Manager Artifact Resolver servlet.
   */
  public SamlArtifactResolve getSamlArtifactResolver() {
    return samlArtifactResolver;
  }

  /**
   * @return The Security Manager Assertion Consumer servlet.
   */
  public SamlAssertionConsumer getSamlAssertionConsumer() {
    return samlAssertionConsumer;
  }

  /**
   * @return The Security Manager Authorization servlet.
   */
  public SamlAuthz getSamlAuthz() {
    return samlAuthz;
  }

  /**
   * @return The Security Manager's authentication controller instance.
   */
  public AuthnController getAuthnController() {
    return authnController;
  }

  /**
   * @return The Security Manager's authentication session-manager instance.
   */
  public AuthnSessionManager getAuthnSessionManager() {
    return authnSessionManager;
  }

  /**
   * @return The Security Manager's authorization controller instance.
   */
  public AuthorizationController getAuthzController() {
    return authzController;
  }

  /**
   * @return The Security Manager's document fetcher controller instance.
   */
  public DocumentFetcherController getDocumentFetcherController() {
    return docFetcherController;
  }

  /**
   * @return The mock HTTP transport.
   */
  public MockHttpTransport getHttpTransport() {
    return transport;
  }

  /**
   * @return The mock user agent.
   */
  public MockHttpClient getUserAgent() {
    return userAgent;
  }

  /**
   * @return The session ID used by the mock GSA and the Security Manager.
   */
  public String getSessionId() {
    return sessionId;
  }

  /**
   * @return The authentication session for the Security Manager, creating it if
   * necessary.  Note that this should <em>not</em> be called until the Security
   * Manager's configuration is set up, because the session uses the
   * configuration in effect when it is created, and will not reflect subsequent
   * changes.
   */
  public AuthnSession makeSession()
      throws IOException {
    return AuthnSession.getInstance(sessionId);
  }

  /**
   * @return The authentication session for the Security Manager.
   * @throws AssertionFailedError if the session hasn't been created yet.
   */
  public AuthnSession getSession() {
    AuthnSession session = authnSessionManager.getSession(sessionId);
    assertNotNull(session);
    return session;
  }

  /**
   * Changes the session ID to a new value and updates the user agent cookie to
   * refer to it.
   */
  public void newSession() {
    sessionId = SessionUtil.generateId();
    setUserAgentCookie(SessionUtil.GSA_SESSION_ID_COOKIE_NAME, sessionId);
    decorator = SessionUtil.getLogDecorator(sessionId);
  }

  /**
   * @return The cookies saved by the mock user agent.
   */
  public CookieStore getUserAgentCookies() {
    return userAgentCookies;
  }

  /**
   * Gets a cookie from the mock user agent.
   *
   * @param name The name of the cookie to retrieve.
   * @return The cookie with the given name, or null if none.
   */
  public GCookie getUserAgentCookieNamed(String name) {
    for (GCookie c : userAgentCookies) {
      if (c.getName().equalsIgnoreCase(name)) {
        return c;
      }
    }
    return null;
  }

  /**
   * Adds a cookie to the mock user agent, replacing any existing cookie with
   * the same name.
   *
   * @param cookie The cookie to add.
   */
  public void setUserAgentCookie(GCookie cookie) {
    // If the cookie is already present, delete it.
    deleteUserAgentCookie(cookie.getName());
    userAgentCookies.add(cookie);
  }

  /**
   * Adds a cookie to the mock user agent, replacing any existing cookie with
   * the same name.
   *
   * @param name The name of the new cookie.
   * @param value The value of the new cookie.
   * @return The new cookie.
   */
  public GCookie setUserAgentCookie(String name, String value) {
    GCookie cookie = GCookie.make(name, value);
    setUserAgentCookie(cookie);
    return cookie;
  }

  /**
   * Adds a cookie to the mock user agent, replacing any existing cookie with
   * the same name.
   *
   * @param name The name of the new cookie.
   * @param value The value of the new cookie.
   * @return The new cookie.
   */
  public GCookie setUserAgentCookie(String name, COOKIE_VALUES value) {
    return setUserAgentCookie(name, value.toString());
  }

  /**
   * Deletes a cookie from the mock user agent.
   *
   * @param name The name of the cookie to delete.
   */
  public void deleteUserAgentCookie(String name) {
    // If the cookie is already present, delete it
    GCookie c = getUserAgentCookieNamed(name);
    if (c != null) {
      userAgentCookies.remove(c);
    }
  }
  
  /**
   * Sets followRedirects
   *
   * @param value Change preference whether to follow redirections by Exchange (true by default) 
   */
  public void setFollowRedirects(boolean value) {
    followRedirects = value;
  }

  /**
   * Starts a test by sending a search request from the mock user agent to the
   * mock GSA, using the default search URL.
   *
   * @return An HTTP exchange object containing the response from the mock GSA.
   */
  public HttpExchange startSearch() {
    return startSearch(getGsaSearchUrl());
  }

  /**
   * @return The PVI string for this session.
   */
  public String getPvi() {
    SessionView view = getSession().getSnapshot().getPrimaryVerifiedView();
    return (view != null) ? view.getUsername() : null;
  }

  /**
   * Starts a test by sending a search request from the mock user agent to the
   * mock GSA, using an alternate search URL.
   *
   * @param url The URL to send the request to.
   * @return An HTTP exchange object containing the response from the mock GSA.
   * @see #addGsaHost
   */
  public HttpExchange startSearch(URL url) {
    startTestMessage();
    try {
      // Initial request to service provider.
      HttpExchange exchange1 = userAgent.getExchange(url);
      exchange1.setFollowRedirects(followRedirects);
      exchange1.exchange();
      return exchange1;
    } catch (IOException e) {
      failWithException(e);
      return null;
    }
  }

  public HttpExchange startDocumentFetch(String documentUrl) {
    startTestMessage();
    try {
      URL url = new URL(getDocFetcherEndpoint(getGsaHost()));
      ListMultimap<String, String> params = ImmutableListMultimap.of("url", documentUrl);
      String content = "url=" + URLEncoder.encode(documentUrl, "UTF8");

      HttpExchange exchange1 = userAgent.postExchange(url, params);

      exchange1.setRequestBody(content.getBytes("UTF-8"));
      exchange1.exchange();
      return exchange1;
    } catch (IOException e) {
      failWithException(e);
      return null;
    }
  }

  /**
   * Starts a test by sending an AuthzQuery to the Security Manager's PDP.
   *
   * @param sampleUrl The sample URL to authorize.
   * @return The authorization status for the given sample URL.
   */
  public AuthzStatus doAuthzQuery(String sampleUrl) {
    startTestMessage();
    try {
      // Submit the request using a SamlClient instance.
      SamlAuthzClient samlClient
          = SamlAuthzClient.make(getMetadata(), Metadata.getSmEntityId(),
              SamlSharedData.make(C.entityIdForGsa(SecurityManagerTestCase.GSA_TESTING_ISSUER),
                  SamlSharedData.Role.AUTHZ_CLIENT, null));
      makeSession();
      SecmgrCredential cred = OpenSamlUtil.makeSecmgrCredential(getSessionId(), "", "", "",
          Collections.<Group>emptyList());
      return
          samlClient.sendAuthzRequest(
              SamlAuthzClient.Protocol.STANDARD,
              ImmutableList.of(sampleUrl),
              cred,
              decorator, -1)
          .get(sampleUrl);
    } catch (IOException | MessageHandlerException e) {
      failWithException(e);
      return null;
    }
  }

  /**
   * Starts a test by sending an authentication request to the Security Manager.
   * @param sessionId The sessionId in request body
   * @return The associated client HttpExchange.
   */
  public HttpExchange doAuthnQuery(MockHttpServletRequest request, String sessionId) {
    return doAuthnQuery(request, sessionId, true);
  }

  /**
   * A version of doAuthnQuery that allows running it without using cookies.
   * By removing cookies from the Authn sequence, we make MockIntegration thread-safe
   * for running concurrency tests -- effectively assuming that we don't care about the user
   * agent's cookie state.
   */
  public HttpExchange doAuthnQuery(MockHttpServletRequest request, String sessionId,
      boolean useCookies) {
    startTestMessage();
    try {
      URL url = new URL(getAuthnServletUrl(getGsaHost()));
      if (useCookies) {
        userAgentCookies.clear();
      }
      HttpExchange exchange1 = userAgent.new MockExchange(request, url);

      exchange1.setRequestBody(sessionId.getBytes("UTF-8"));
      exchange1.exchange();
      return exchange1;
    } catch (IOException e) {
      failWithException(e);
      return null;
    }
  }

  private void startTestMessage() {
    Preconditions.checkNotNull(testName);
    logger.info(decorator.apply(
        ((testNameCounter > 0)
            ? "part " + testNameCounter + " of"
            : "start")
        + " test: " + testName));
    testNameCounter += 1;
  }

  public static void failWithException(Exception e) {
    AssertionFailedError f = new AssertionFailedError("Caught exception during test: ");
    f.initCause(e);
    throw f;
  }

  // **************** Testing helpers ****************

  public void assertContentResult(HttpExchange exchange) {
    assertContentResult(SP_SUCCESS_TEXT, exchange);
  }

  public void assertContentResult(String contentText, HttpExchange exchange) {
    assertResultText("Did not see expected successful content results", contentText, exchange);
  }

  public void assertContentResult(int nGood, HttpExchange exchange) {
    assertContentResult(exchange);
    assertGoodGroups(nGood);
  }

  public Element assertLoginFormResult(HttpExchange exchange) {
    return assertFormResult(LOGIN_FORM_TEXT, exchange);
  }

  public Element assertPostBindingResult(HttpExchange exchange) {
    return assertFormResult(POST_BINDING_TEXT, exchange);
  }

  public Element assertFormResult(String formText, HttpExchange exchange) {
    return assertFormText(formText, getResponseText(exchange));
  }

  private Element assertLoginFormText(String entity) {
    return assertFormText(LOGIN_FORM_TEXT, entity);
  }

  private Element assertFormText(String formText, String entity) {
    assertResultText("Did not see expected login form", formText, entity);
    Element form = parseHtmlForm(entity);
    assertPostForm(form);
    return form;
  }

  public void assertLoginFormResult(int nGood, HttpExchange exchange) {
    assertLoginFormResult(exchange);
    assertGoodGroups(nGood);
  }

  public void assertExchangeStatusOk(HttpExchange exchange) {
    assertStatusResult(SC_OK, exchange);
  }

  public void assertFailureResult(HttpExchange exchange) {
    assertStatusResult(SC_FORBIDDEN, exchange);
  }

  public void assertServerErrorResult(HttpExchange exchange) {
    assertStatusResult(SC_INTERNAL_SERVER_ERROR, exchange);
  }

  public void assertStatusResult(int statusCode, HttpExchange exchange) {
    assertEquals("Incorrect response status code", statusCode, exchange.getStatusCode());
  }

  public void assertStatusResult(int statusCode, int nGood, HttpExchange exchange) {
    assertStatusResult(statusCode, exchange);
    assertGoodGroups(nGood);
  }

  public void assertRedirect(HttpExchange exchange, String redirectUrl) {
    assertTrue("Incorrect response status code",
        ServletBase.isRedirectStatus(exchange.getStatusCode()));
    String location = exchange.getResponseHeaderValue("Location");
    int query = location.indexOf('?');
    assertEquals("Incorrect redirect URL", redirectUrl,
        (query > 0) ? location.substring(0, query) : location);
  }

  public void assertCredGroupEnabled(int n, HttpExchange exchange) {
    for (Element input : getCredGroupInputs(n, exchange)) {
      assertTrue("Credential group " + n + " is disabled",
          input.getAttribute(HtmlParser.ATTR_DISABLED).isEmpty());
    }
  }

  public void assertCredGroupDisabled(int n, HttpExchange exchange) {
    for (Element input : getCredGroupInputs(n, exchange)) {
      assertFalse("Credential group " + n + " is enabled",
          input.getAttribute(HtmlParser.ATTR_DISABLED).isEmpty());
    }
  }

  private List<Element> getCredGroupInputs(int n, HttpExchange exchange) {
    String entity = getResponseText(exchange);
    Element form = assertLoginFormText(entity);
    NodeList inputs = form.getElementsByTagName(HtmlParser.TAG_INPUT);
    List<Element> result = Lists.newArrayList();
    for (int i = 0; i < inputs.getLength(); i++) {
      Element input = (Element) inputs.item(i);
      String name = input.getAttribute(HtmlParser.ATTR_NAME);
      if (("ugroup" + n).equals(name) || ("pwgroup" + n).equals(name)) {
        result.add(input);
      }
    }
    assertEquals("Credential group " + n + " inputs incorrect", 2, result.size());
    return result;
  }

  public void assertCredGroupActive(int n, HttpExchange exchange) {
    String entity = getResponseText(exchange);
    assertLoginFormText(entity);
    assertTrue("Credential group " + n + " isn't active",
        matchActivityStyle("group" + n + "Active", "inline", entity) &&
        matchActivityStyle("group" + n + "Inactive", "none", entity));
  }

  public void assertCredGroupInactive(int n, HttpExchange exchange) {
    String entity = getResponseText(exchange);
    assertLoginFormText(entity);
    assertTrue("Credential group " + n + " isn't inactive",
        matchActivityStyle("group" + n + "Active", "none", entity) &&
        matchActivityStyle("group" + n + "Inactive", "inline", entity));
  }

  private boolean matchActivityStyle(String id, String value, String entity) {
    return entity.contains("#" + id + " {display:" + value + "; }");
  }

  public void assertResultText(String message, String matchText, HttpExchange exchange) {
    assertResultText(message, matchText, getResponseText(exchange));
  }

  public void assertResultText(String message, String matchText, String entity) {
    assertTrue(message, entity.contains(matchText));
  }

  private String getResponseText(HttpExchange exchange) {
    assertExchangeStatusOk(exchange);
    try {
      return exchange.getResponseEntityAsString();
    } catch (IOException e) {
      failWithException(e);
      throw new IllegalStateException();
    }
  }

  /**
   * Assert that this many credential groups are verified.
   */
  private void assertGoodGroups(int nGood) {
    assertEquals("Incorrect number of verified groups", nGood, countGoodGroups());
  }

  /**
   * @return The number of verified credential groups in the current session.
   */
  private int countGoodGroups() {
    int nGood = 0;
    SessionSnapshot snapshot = getSession().getSnapshot();
    for (CredentialGroup credentialGroup : snapshot.getConfig().getCredentialGroups()) {
      if (snapshot.getView(credentialGroup).isSatisfied(true)) {
        nGood += 1;
      }
    }
    return nGood;
  }

  public void assertTrustDuration(long trustDuration) {
    assertExpirationTime(DateTimeUtils.currentTimeMillis() + trustDuration);
  }

  private void assertExpirationTime(long expectedExpirationTime) {
    long expirationTime = (Long) userAgent.getSession().getAttribute("expirationTime");
    assertTrue("Expiration time didn't match;"
        + " expected: " + new DateTime(expectedExpirationTime).toString()
        + " actual: " + new DateTime(expirationTime).toString(),
        Math.abs(expirationTime - expectedExpirationTime) < 1000);
  }

  /**
   * This method should be called when the test has generated a login form that
   * it's not going to fill in.  After checking that the login form is present,
   * it initiates a new request, which should generate an error because the
   * authn controller is waiting for the form to be filled out, and instead gets
   * a new request.  The error recovery resets the controller to the IDLE state,
   * so that the next request will be processed normally.
   */
  public void assertUnusedLoginForm(HttpExchange exchange) {
    // Start the test and get the login form back.
    assertLoginFormResult(exchange);

    // The next request results in an error because we left the server in a bad state.
    assertServerErrorResult(startSearch());
  }

  private void assertPostForm(Element form) {
    String method = getRequiredAttribute(form, HtmlParser.ATTR_METHOD);
    assertTrue("<form> method not POST", HtmlParser.FORM_METHOD_POST.equalsIgnoreCase(method));
  }

  // **************** Form posting ****************

  public HttpExchange processPostForm(HttpExchange exchange, ListMultimap<String, String> params) {
    return processPostForm(parseHtmlForm(getResponseText(exchange)), params, exchange.getCookies());
  }

  public HttpExchange processPostForm(HttpExchange exchange) {
    return processPostForm(exchange, newParams());
  }

  public HttpExchange processPostForm(Element form, ListMultimap<String, String> params,
      CookieStore cookies) {
    assertPostForm(form);
    collectHiddenFormBindings(form, params);
    return submitPostForm(form, params, cookies);
  }

  public HttpExchange processPostForm(Element form, CookieStore cookies) {
    return processPostForm(form, newParams(), cookies);
  }

  private static ListMultimap<String, String> newParams() {
    return ArrayListMultimap.create();
  }

  private Element parseHtmlForm(String formText) {
    try {
      return getUniqueElement(HtmlParser.parse(formText), HtmlParser.TAG_FORM);
    } catch (IOException e) {
      failWithException(e);
      throw new IllegalStateException();
    }
  }

  private void collectHiddenFormBindings(Element form, ListMultimap<String, String> params) {
    NodeList inputs = form.getElementsByTagName(HtmlParser.TAG_INPUT);
    for (int i = 0; i < inputs.getLength(); i++) {
      Element input = (Element) inputs.item(i);
      if ("hidden".equalsIgnoreCase(input.getAttribute(HtmlParser.ATTR_TYPE))) {
        params.put(
            getRequiredAttribute(input, HtmlParser.ATTR_NAME),
            getRequiredAttribute(input, HtmlParser.ATTR_VALUE));
      }
    }
  }

  private HttpExchange submitPostForm(Element form, ListMultimap<String, String> params,
      CookieStore cookies) {
    String action = getRequiredAttribute(form, HtmlParser.ATTR_ACTION);
    try {
      HttpExchange exchange = userAgent.postExchange(new URL(action), params);
      exchange.addCookies(cookies);
      exchange.setFollowRedirects(followRedirects);
      exchange.exchange();
      return exchange;
    } catch (IOException e) {
      failWithException(e);
      return null;
    }
  }

  private static Element getUniqueElement(Document document, String name) {
    NodeList nodes = document.getElementsByTagName(name);
    assertEquals("Wrong number of <" + name + "> elements in response", 1, nodes.getLength());
    return (Element) nodes.item(0);
  }

  private static String getRequiredAttribute(Element element, String name) {
    String value = element.getAttribute(name);
    assertFalse("Missing " + name + " attribute", value.isEmpty());
    return StringEscapeUtils.unescapeHtml4(value);
  }

  // **************** Exchange Logs ****************

  // TODO: these methods assume that the mock back-end servers do forms
  // auth.  We need to support other server types.

  /**
   * Creates an exchange log representing the initial HTTP exchange for a GSA
   * search.  This includes the initial search request to the GSA and the
   * redirect to the Security Manager.  It optionally includes some messages
   * exchanged between the Security Manager and the mock back-end servers.
   *
   * @param items The expected exchanges between the Security Manager and the
   *     mock back-end servers.
   * @return The specified exchange log.
   */
  public static LogItem standardLogPrefix(LogItem... items) {
    return standardLogPrefix(MockServiceProvider.class.getSimpleName(), items);
  }

  /**
   * Creates an exchange log representing the initial HTTP exchange for a GSA
   * search.  This includes the initial search request to the GSA and the
   * redirect to the Security Manager.  It optionally includes some messages
   * exchanged between the Security Manager and the mock back-end servers.
   *
   * @param serviceProvider The service provider to expect.
   * @param items The expected exchanges between the Security Manager and the
   *     mock back-end servers.
   * @return The specified exchange log.
   */
  public static LogItem standardLogPrefix(String serviceProvider, LogItem... items) {
    return logSequence(
        // Contact mock GSA,
        logGet(serviceProvider),
        // which redirects to SecMgr,
        logRedirect(SamlAuthn.class.getSimpleName(), items));
  }

  /**
   * Creates an exchange log representing a successful search result.  This
   * includes the redirect from the Security Manager to the GSA, and the
   * successful search result from the GSA to the user agent.
   */
  public static LogItem successfulLogSuffix() {
    return artifactLogSuffix(SC_OK,
        MockArtifactConsumer.class.getSimpleName(),
        MockServiceProvider.class.getSimpleName());
  }

  /**
   * Creates an exchange log representing an unsuccessful search result.  This
   * includes the redirect from the Security Manager to the GSA, and the
   * unsuccessful search result from the GSA to the user agent.  Note that the
   * mock GSA returns a 401 response if authentication is unsuccessful; this is
   * not an accurate depiction of the GSA's behavior, but it does simplify
   * testing.
   */
  public static LogItem unsuccessfulLogSuffix() {
    return artifactLogSuffix(SC_FORBIDDEN,
        MockArtifactConsumer.class.getSimpleName(),
        MockServiceProvider.class.getSimpleName());
  }

  /**
   * Creates an exchange log representing a search result using POST binding
   * with a given assertion consumer.
   */
  public static LogItem postLogSuffix(int statusCode, String assertionConsumer) {
    return logSequence(
        // The security manager responds with a "POST redirect",
        logOk(),
        // which the user agent posts to the assertion consumer.
        logPost(assertionConsumer),
        logResponse(statusCode));
  }

  /**
   * Creates an exchange log representing a search result using artifact binding
   * with a given assertion consumer and no service provider.
   */
  public static LogItem artifactLogSuffix(int statusCode, String assertionConsumer) {
    return logSequence(
        // The SecMgr creates an artifact and redirects to the assertion
        // consumer,
        logRedirect(assertionConsumer,
            // which posts a request to the SecMgr's artifact resolver
            logPost(SamlArtifactResolve.class.getSimpleName()),
            // which resolves the artifact.
            logOk()),
        logResponse(statusCode));
  }

  /**
   * Creates an exchange log representing a search result using artifact binding
   * with a given assertion consumer and service provider.
   */
  public static LogItem artifactLogSuffix(int statusCode, String assertionConsumer,
      String serviceProvider) {
    return logSequence(
        // The SecMgr creates an artifact and redirects to the assertion
        // consumer,
        logRedirect(assertionConsumer,
            // which posts a request to the SecMgr's artifact resolver
            logPost(SamlArtifactResolve.class.getSimpleName()),
            // which resolves the artifact.
            logOk()),
        // The assertion consumer redirects to the service provider,
        logRedirect(serviceProvider),
        // which responds with final result.
        logResponse(statusCode));
  }

  /**
   * Creates an exchange log representing the response to an unfinished
   * authentication request.  Basically this is just a response containing the
   * ULF.
   */
  public static LogItem unfinishedLogSuffix() {
    return renderUlf();
  }

  /**
   * Creates an exchange log representing a ULF interaction.  This is a response
   * containing the ULF, followed by a POST back to the Security Manager
   * containing the POSTed variables.  It optionally includes some messages
   * exchanged between the Security Manager and the mock back-end servers after
   * the return to the Security Manager.
   *
   * @param items The expected exchanges between the Security Manager and the
   *     mock back-end servers.
   * @return The specified exchange log.
   */
  public static LogItem ulfExchange(LogItem... items) {
    return logSequence(
        renderUlf(),
        logPost(SamlAuthn.class.getSimpleName(), items));
  }

  /**
   * @return An exchange log representing a ULF response.
   */
  public static LogItem renderUlf() {
    return logOk();
  }

  /**
   * Creates an exchange log representing a successful sample-URL check between
   * the Security Manager and a mock content server.
   *
   * @param status The HTTP status returned by the mock content server.
   * @return The specified exchange log.
   */
  public static LogItem successfulSampleUrlCheck(int status) {
    return logSequence(
        // Contact mock content server,
        logGet(MockContentServer.class.getSimpleName()),
        // which returns a valid response..
        logResponse(status));
  }

  /**
   * Creates an exchange log representing an unsuccessful sample-URL check
   * between the Security Manager and a mock content server.  This specifically
   * assumes that the content server redirects to a mock forms-auth server.
   *
   * @param status The HTTP status returned by the mock forms-auth server.
   * @param servletName The class name of the mock forms-auth server.
   * @return The specified exchange log.
   */
  public static LogItem unsuccessfulSampleUrlCheck(int status, String servletName) {
    return logSequence(
        // Contact mock content server,
        logGet(MockContentServer.class.getSimpleName()),
        // which redirects to mock form-auth server,
        logRedirect(servletName),
        // which returns a valid response.
        logResponse(status));
  }

  /**
   * Creates an exchange log representing the Security Manager getting a form
   * from a mock forms-auth server and submitting good credentials to the form.
   *
   * @param servletName The class name of the mock forms-auth server.
   * @return The specified exchange log.
   */
  public static LogItem sendGoodCredsToAuthServer(String servletName) {
    return logSequence(
        // Get form from auth server.
        getFormFromAuthServer(servletName),
        // Post filled-out form back to auth server,
        logPost(servletName),
        // The server accepts, redirecting to content server,
        logRedirect(MockContentServer.class.getSimpleName()),
        // causing the content server to return a valid response.
        logResponse(SC_PARTIAL_CONTENT));
  }

  /**
   * Creates an exchange log representing the Security Manager getting a form
   * from a mock forms-auth server and submitting bad credentials to the form.
   *
   * @param servletName The class name of the mock forms-auth server.
   * @return The specified exchange log.
   */
  public static LogItem sendBadCredsToAuthServer(String servletName) {
    return logSequence(
        // Get form from auth server.
        getFormFromAuthServer(servletName),
        // Post filled-out form back to auth server,
        logPost(servletName),
        // which the server rejects.
        logForbidden());
  }

  /**
   * Creates an exchange log representing the Security Manager getting a form
   * from a mock forms-auth server.  This represents a request to a mock content
   * server that's redirected to a mock forms-auth server that returns a form.
   *
   * @param servletName The class name of the mock forms-auth server.
   * @return The specified exchange log.
   */
  public static LogItem getFormFromAuthServer(String servletName) {
    return logSequence(
        // Contact mock content server,
        logGet(MockContentServer.class.getSimpleName()),
        // which redirects to mock form-auth server,
        logRedirect(servletName),
        // which returns a form.
        logOk());
  }

  /**
   * Resets the exchange log, removing all of the entries.
   */
  public void resetExchangeLog() {
    transport.resetExchangeLog();
  }

  /**
   * Compares the exchange log to a given expected log.
   *
   * @param item The expected log.
   * @throws AssertionFailedError if the logs don't match.
   */
  public void checkExchangeLog(LogItem item) {
    List<ExchangeLog> expectedExchanges = ExchangeLog.convertLogItem(item);
    List<ExchangeLog> exchangeLogs = transport.getExchangeLogs();
    try {
      ExchangeLog.assertListsOfExchangeLogsMatch(expectedExchanges, exchangeLogs);
    } catch (IllegalStateException e) {
      throw new AssertionFailedError(
          e.getMessage() + ":\n"
          + "\nexpected:\n" + ExchangeLog.stringifyLogItem(item)
          + "\nactual:\n" + ExchangeLog.stringifyExchangeLogs(exchangeLogs));
    } finally {
      transport.resetExchangeLog();
    }
  }
}
