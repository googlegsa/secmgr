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

package com.google.enterprise.secmgr.mock;

import com.google.common.collect.ImmutableMap;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.mock.MockContentServer.COOKIE_VALUES;
import com.google.enterprise.secmgr.testing.ServletTestUtil;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import java.util.logging.Logger;
import javax.annotation.concurrent.Immutable;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A base class for implementing mock cookie-based authentication servers.
 */
public abstract class MockFormAuthServer extends ServletBase
    implements GettableHttpServlet, PostableHttpServlet, MockServer {
  private static final Logger logger = Logger.getLogger(MockFormAuthServer.class.getName());

  public static final String CONTENT_URL_PARAM_NAME = "contentUrl";
  // This cookie is set during the presentation of the login form and required
  // when parsing it's results.  Simulates a common use-case requirement.
  private static final String INTERNAL_REQUIRED_COOKIE_NAME = "myCookie";
  private static final String INTERNAL_REQUIRED_COOKIE_VALUE = "myValue";

  /**
   * Look for this string in the HTTP response to detect the form.
   */
  public static final String FORM_MATCH_STRING = "Just another form from LA";

  private final String usernameKey;
  private final String passwordKey;
  private final String cookieName;
  private final boolean useRedirectParam;
  private final ImmutableMap<String, String> passwordMap;
  private final ImmutableMap<String, String> cookieValueMap;
  private final ImmutableMap<String, String> inputTypes;
  private final MockContentServer contentServer;
  private IOException exceptionOnNextRequest;

  protected MockFormAuthServer(String usernameKey, String passwordKey, String cookieName,
      String contextUrl, boolean useRedirectParam, ImmutableMap<String, String> passwordMap,
      ImmutableMap<String, String> cookieValueMap) {
    this.usernameKey = usernameKey;
    this.passwordKey = passwordKey;
    this.cookieName = cookieName;
    this.useRedirectParam = useRedirectParam;
    this.passwordMap = passwordMap;
    this.cookieValueMap = cookieValueMap;
    inputTypes = ImmutableMap.of(
        usernameKey, "text",
        passwordKey, "password");
    contentServer
        = new MockContentServer(cookieName, contextUrl,
            useRedirectParam ? CONTENT_URL_PARAM_NAME : null);
  }

  public String getCookieName() {
    return cookieName;
  }

  public void setCookieDomain(String cookieDomain) {
    contentServer.setCookieDomain(cookieDomain);
  }

  public void setCookiePath(String cookiePath) {
    contentServer.setCookiePath(cookiePath);
  }

  public GCookie makeCookie(String name, String value) {
    return contentServer.makeCookie(name, value);
  }

  public MockContentServer getContentServer() {
    return contentServer;
  }

  @Override
  public void addToIntegration(MockIntegration integration)
      throws ServletException {
    MockHttpTransport transport = integration.getHttpTransport();
    contentServer.addToIntegration(integration);
    if (getLoginUrl() != null) {
      transport.registerServlet(getLoginUrl(), this);
    }
  }

  @Override
  public String getContextUrl() {
    return contentServer.getContextUrl();
  }

  @Override
  public String getSampleUrl() {
    return contentServer.getSampleUrl();
  }

  @Override
  public void reset() {
    contentServer.reset();
    exceptionOnNextRequest = null;
  }
  
  public void setExceptionToBeThrownOnNextRequest(IOException e) {
    exceptionOnNextRequest = e;
  }

  public String getLoginUrl() {
    return contentServer.getRedirectUrl();
  }

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    if (exceptionOnNextRequest != null) {
      throw exceptionOnNextRequest;
    }
    if (getLoginUrl() == null) {
      doGetWithBasicAuth(request, response);
      return;
    }
    int goodStatus = ServletTestUtil.goodHttpStatusFor(request);

    COOKIE_VALUES cookieInstructions = getCookieInstructions(request);
    if (cookieInstructions == COOKIE_VALUES.CRACK_FA_STOP) {
      initNormalResponseWithHeaders(response, goodStatus, HttpUtil.COOKIE_CRACK_USERNAME_HEADER,
          COOKIE_VALUES.CRACK_FA_STOP.toString());
      return;
    }

    PrintWriter writer = (cookieInstructions == COOKIE_VALUES.CRACK_FA_FORM) ?
        initNormalResponseWithHeaders(response, goodStatus,
            HttpUtil.COOKIE_CRACK_USERNAME_HEADER, COOKIE_VALUES.CRACK_FA_FORM.toString())
        : initNormalResponse(response, goodStatus);

    GCookie.addHttpResponseCookie(
        makeCookie(INTERNAL_REQUIRED_COOKIE_NAME, INTERNAL_REQUIRED_COOKIE_VALUE),
        response);
    writer.write(
        "<html><head><title>" + FORM_MATCH_STRING + "</title><body>\n"
        + "<h1>Please login</h1>\n"
        + "<form method=\"post\" action=\"" + HttpUtil.getRequestUrl(request, false) + "\">\n");
    for (Map.Entry<String, String> entry : inputTypes.entrySet()) {
      writer.write("<input name=\"" + entry.getKey() + "\""
                   + " type=\"" + entry.getValue() + "\" /><br>\n");
    }
    writer.write("<input type=\"hidden\" name=\""
                 + CONTENT_URL_PARAM_NAME
                 + "\" value=\""
                 + (useRedirectParam
                     ? request.getParameter(CONTENT_URL_PARAM_NAME)
                     : request.getHeader(HttpUtil.HTTP_HEADER_REFERRER))
                 + "\" />\n");
    writer.write("</form></body></html>\n");
    writer.close();
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    if (exceptionOnNextRequest != null) {
      throw exceptionOnNextRequest;
    }
    String username = request.getParameter(usernameKey);
    String password = request.getParameter(passwordKey);
    if (username == null || username.isEmpty() ||
        password == null || password.isEmpty() ||
        !password.equals(passwordMap.get(username)) ||
        !checkForInternalCookie(request)) {
      failedLoginResponse(response);
      return;
    }
    String contentUrl = request.getParameter(CONTENT_URL_PARAM_NAME);
    if (contentUrl == null || contentUrl.isEmpty()) {
      initErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST);
      return;
    }
    String cookieValue = cookieValueMap.get(username);
    if (cookieValue != null) {
      GCookie.addHttpResponseCookie(makeCookie(cookieName, cookieValue), response);
    }
    initResponse(response);
    response.sendRedirect(contentUrl);
  }

  public void failedLoginResponse(HttpServletResponse response)
      throws IOException {
    initErrorResponse(response, HttpServletResponse.SC_FORBIDDEN);
  }

  private void doGetWithBasicAuth(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String realm = "unused"; // this doesn't seem to be really needed
    String username = MockBasicAuthServer.getValidAuthCredential(request, passwordMap, realm);
    if (username != null) {
      logger.info("doGetWithBasicAuth - got good credentials, setting cookie and redirecting");
      String contentUrl = request.getParameter(CONTENT_URL_PARAM_NAME);
      String cookieValue = cookieValueMap.get(username);
      if (cookieValue != null) {
        GCookie.addHttpResponseCookie(makeCookie(cookieName, cookieValue), response);
      }
      initResponse(response);
      response.sendRedirect(contentUrl);
    } else {
      logger.info("doGetWithBasicAuth - got bad or no credentials, prompting 401");
      response.addHeader(HttpUtil.HTTP_HEADER_WWW_AUTHENTICATE, "Basic realm=\"" + realm + "\"");
      initErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED);
    }
  }

  private boolean checkForInternalCookie(HttpServletRequest request) {
    Cookie c = MockContentServer.findCookie(request.getCookies(), INTERNAL_REQUIRED_COOKIE_NAME);
    if (c == null) { return false; }
    return (c.getValue().equalsIgnoreCase(INTERNAL_REQUIRED_COOKIE_VALUE));
  }

  private COOKIE_VALUES getCookieInstructions(HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies != null) {
      for (Cookie c : request.getCookies()) {
        if (cookieName.equals(c.getName())) {
          try {
            return COOKIE_VALUES.valueOf(c.getValue());
          } catch (IllegalArgumentException e) {
            // Ignore this cookie.
          }
        }
      }
    }
    // No matching values, so return nothing.
    return null;
  }

  /**
   * A mock server that uses HTTP BASIC authentication with cookies.
   */
  @Immutable
  public static class Basic1 extends MockFormAuthServer {
    public static final String USERNAME_KEY = "username";
    public static final String PASSWORD_KEY = "password";
    public static final String GOOD_USERNAME = "ruth";
    public static final String GOOD_PASSWORD = "test";
    public static final String COOKIE_NAME = "Server1ID";

    public Basic1(String contextUrl) {
      super(USERNAME_KEY, PASSWORD_KEY, COOKIE_NAME, contextUrl, true,
          ImmutableMap.of(GOOD_USERNAME, GOOD_PASSWORD),
          ImmutableMap.of(GOOD_USERNAME, MockContentServer.COOKIE_VALUES.VALID.toString()));
    }
  }

  /**
   * A mock server that uses form authentication with cookies.
   */
  @Immutable
  public static class Form1 extends MockFormAuthServer {
    public static final String USERNAME_KEY = "username";
    public static final String PASSWORD_KEY = "password";
    public static final String GOOD_USERNAME = "joe";
    public static final String GOOD_PASSWORD = "plumber";
    public static final String COOKIE_NAME = "Server1ID";

    public Form1(String contextUrl, boolean useRedirectParam) {
      super(USERNAME_KEY, PASSWORD_KEY, COOKIE_NAME, contextUrl, useRedirectParam,
          ImmutableMap.of(GOOD_USERNAME, GOOD_PASSWORD),
          ImmutableMap.of(GOOD_USERNAME, MockContentServer.COOKIE_VALUES.VALID.toString()));
    }

    public Form1(String contextUrl) {
      this(contextUrl, false);
    }
  }

  /**
   * A different mock server that uses form authentication with cookies.  This
   * one uses different credentials and a different cookie.
   */
  @Immutable
  public static class Form2 extends MockFormAuthServer {
    public static final String USERNAME_KEY = "username";
    public static final String PASSWORD_KEY = "password";
    public static final String GOOD_USERNAME = "jim";
    public static final String GOOD_PASSWORD = "electrician";
    public static final String COOKIE_NAME = "Server2ID";

    public Form2(String contextUrl) {
      super(USERNAME_KEY, PASSWORD_KEY, COOKIE_NAME, contextUrl, false,
          ImmutableMap.of(GOOD_USERNAME, GOOD_PASSWORD),
          ImmutableMap.of(GOOD_USERNAME, MockContentServer.COOKIE_VALUES.VALID.toString()));
    }
  }

  /**
   * This MockFormAuthServer generates a redirect back to itself during a login
   * failure rather than the default behavior of returning a 401/403.
   */
  @Immutable
  public static class Form3 extends MockFormAuthServer {
    public static final String USERNAME_KEY = "username";
    public static final String PASSWORD_KEY = "password";
    public static final String GOOD_USERNAME = "jim";
    public static final String GOOD_PASSWORD = "electrician";
    public static final String COOKIE_NAME = "Server2ID";

    public Form3(String contextUrl) {
      super(USERNAME_KEY, PASSWORD_KEY, COOKIE_NAME, contextUrl, false,
          ImmutableMap.of(GOOD_USERNAME, GOOD_PASSWORD),
          ImmutableMap.of(GOOD_USERNAME, MockContentServer.COOKIE_VALUES.VALID.toString()));
    }

    @Override
    public void failedLoginResponse(HttpServletResponse response)
        throws IOException {
      response.sendRedirect(getLoginUrl());
    }
  }
}
