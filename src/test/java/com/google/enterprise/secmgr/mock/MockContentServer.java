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

package com.google.enterprise.secmgr.mock;

import com.google.common.base.Strings;
import com.google.common.net.UrlEscapers;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.config.AuthnMechSampleUrl;
import com.google.enterprise.secmgr.testing.ServletTestUtil;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Implements a mock content server that is protected by form authentication.  If an
 * incoming request has an appropriate cookie, it is granted access to the content.
 * Otherwise, it's redirected to the authentication form.
 */
public class MockContentServer extends ServletBase
    implements GettableHttpServlet, MockServer {

  /**
   * A set of magic cookie values that affect this server's behavior.
   */
  public enum COOKIE_VALUES {
                    // Cookies with this value:
    VALID,          //   are valid for content retrieval (but not crackable)
    INVALID,        //   are never accepted.
    VALID_ONCE,     //   are accepted once, and then transformed to INVALID.
    EXPIRED,        //   are not accepted, and transformed to INVALID.
    SUDDEN_DEATH,   //   cause the content server to return a 404 error.
    CRACK_CS_GET,   //   cause cookie cracking during the content server GET,
                    //     and allow immediate content access.
    CRACK_CS_GET_EMPTY,    // Same as above, but generates an empty cracked username.
    CRACK_CS_STOP,  //   cause cookie cracking during the content server GET,
                    //     and return an otherwise blank SC_OK page.
    CRACK_CS_GROUP_STOP,    // crack both username and groups during  login form, and stop.
    CRACK_CS_GROUP_ONLY_STOP,  // crack groups (only) during  login form, and stop.
    CRACK_CS_GROUP_EMPTY_STOP, // crack username but emit an empty groups header.
    CRACK_CS_REDIR, //   cause cookie cracking during the redirect to forms auth.
    CRACK_FA_FORM,  //   cause cookie cracking during the presentation of the login form.
    CRACK_FA_STOP,  //   cause cookie cracking instead of presentation of the login form.
    CS_REDIR_VALID_ONCE,    //   cause the content server to change the value of the
                    //     cookie to VALID_ONCE, and redirect to the URL specified
                    //     in the CGI param RETURN_PATH
    CS_REDIR_INVALID,       // similar to above, but post-redirect set cookie INVALID.
    OTHER           //   are ignored.
  }

  /**
   * Look for this string in the HTTP response to detect the content.
   */
  public static final String CONTENT_MATCH_STRING = "Just another site from LA";

  private static final String CRACKED_GROUPS_LIST = "group1,group2,group3";

  private final String cookieName;
  private final String contextUrl;
  private final String sampleUrl;
  private final String redirectUrl;
  private final String redirectParam;

  private String cookieDomain;
  private String cookiePath;
  // If true, causes the content server to return a blank SC_OK page..
  private boolean hasIllness;

  public MockContentServer(String cookieName, String contextUrl, String redirectParam) {
    this.cookieName = cookieName;
    this.contextUrl = contextUrl;
    this.sampleUrl = contextUrl + "/sample";
    this.redirectUrl = contextUrl + "/redirect";
    this.redirectParam = redirectParam;
    reset();
  }

  @Override
  public void addToIntegration(MockIntegration integration)
      throws ServletException {
    MockHttpTransport transport = integration.getHttpTransport();
    transport.registerContextUrl(contextUrl);
    transport.registerServlet(sampleUrl, this);
  }

  @Override
  public String getContextUrl() {
    return contextUrl;
  }

  @Override
  public String getSampleUrl() {
    return sampleUrl;
  }

  public String getRedirectUrl() {
    return redirectUrl;
  }

  public String getRedirectParam() {
    return redirectParam;
  }

  @Override
  public void reset() {
    cookieDomain = null;
    cookiePath = null;
    hasIllness = false;
  }

  public void setCookieDomain(String cookieDomain) {
    this.cookieDomain = cookieDomain;
  }

  public void setCookiePath(String cookiePath) {
    this.cookiePath = cookiePath;
  }

  public void makeIll() {
    hasIllness = true;
  }

  public GCookie makeCookie(String name, String value) {
    GCookie.Builder builder = GCookie.builder(name).setValue(value);
    if (cookieDomain != null) {
      builder.setDomain(cookieDomain);
    }
    if (cookiePath != null) {
      builder.setPath(cookiePath);
    }
    return builder.build();
  }

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {

    if (hasIllness) {
      initResponse(response);
      return;
    }

    Cookie cookie = findCookie(request.getCookies(), cookieName);
    COOKIE_VALUES cookieValue = COOKIE_VALUES.OTHER;
    if (cookie != null) {
      try {
        cookieValue = COOKIE_VALUES.valueOf(cookie.getValue());
      } catch (IllegalArgumentException e) {
        cookieValue = COOKIE_VALUES.OTHER;
      }
    }
    int goodStatus = ServletTestUtil.goodHttpStatusFor(request);

    switch (cookieValue) {
      case VALID:
        emitContent(request, response, goodStatus, null);
        break;

      case VALID_ONCE:
        GCookie.addHttpResponseCookie(
            setCookieValue(cookie, COOKIE_VALUES.INVALID.toString()),
            response);
        emitContent(request, response, goodStatus, null);
        break;

      case EXPIRED:
        GCookie.addHttpResponseCookie(
            setCookieValue(cookie, COOKIE_VALUES.INVALID.toString()),
            response);
        emitRedirect(request, response, redirectUrl, null);
        break;

      case SUDDEN_DEATH:
        initErrorResponse(response, HttpServletResponse.SC_NOT_FOUND);
        break;

      case CRACK_CS_GET:
        emitContent(request, response, goodStatus, cookieValue.toString());
        break;

      case CRACK_CS_GET_EMPTY:
        emitContent(request, response, goodStatus, "");
        break;

      case CRACK_CS_STOP:
        initNormalResponseWithHeaders(response, goodStatus,
            HttpUtil.COOKIE_CRACK_USERNAME_HEADER, cookieValue.toString());
        break;

      case CRACK_CS_REDIR:
        emitRedirect(request, response, redirectUrl, cookieValue.toString());
        break;

      case CRACK_CS_GROUP_STOP:
        initNormalResponseWithHeaders(response, goodStatus,
            HttpUtil.COOKIE_CRACK_USERNAME_HEADER, cookieValue.toString(),
            HttpUtil.COOKIE_CRACK_GROUPS_HEADER, CRACKED_GROUPS_LIST);
        break;

      case CRACK_CS_GROUP_ONLY_STOP:
        initNormalResponseWithHeaders(response, goodStatus,
            HttpUtil.COOKIE_CRACK_GROUPS_HEADER, CRACKED_GROUPS_LIST);
        break;

      case CRACK_CS_GROUP_EMPTY_STOP:
        initNormalResponseWithHeaders(response, goodStatus,
            HttpUtil.COOKIE_CRACK_USERNAME_HEADER, cookieValue.toString(),
            HttpUtil.COOKIE_CRACK_GROUPS_HEADER, "");
        break;

      case CS_REDIR_VALID_ONCE:
        changeCookieAndRedir(request, response, cookie, COOKIE_VALUES.VALID_ONCE);
        break;

      case CS_REDIR_INVALID:
        changeCookieAndRedir(request, response, cookie, COOKIE_VALUES.INVALID);
        break;

      case INVALID:
      default:
        emitRedirect(request, response, redirectUrl, null);
        break;
    }
  }

  private void emitContent(HttpServletRequest request, HttpServletResponse response, int status,
      String crackedName)
      throws IOException {
    String returnPath = request.getParameter(AuthnMechSampleUrl.DEFAULT_RETURN_URL_PARAMETER);
    if (!Strings.isNullOrEmpty(returnPath)) {
      initResponse(response);
      response.sendRedirect(returnPath);
      return;
    }
    PrintWriter writer = initNormalResponseWithHeaders(response, status,
        HttpUtil.COOKIE_CRACK_USERNAME_HEADER, crackedName);
    writer.write(
        "<http><head><title>" + CONTENT_MATCH_STRING + "</title><body>\n"
        + "<h1>Just another site from LA</h1>\n"
        + "<p>Welcome to the machine!</p>\n"
        + "</body></http>\n");
    writer.close();
  }

  private void emitRedirect(HttpServletRequest request, HttpServletResponse response,
      String redirectTo, String crackedName)
      throws IOException {
    initResponse(response);
    if (crackedName != null) {
      response.addHeader(HttpUtil.COOKIE_CRACK_USERNAME_HEADER, crackedName);
    }
    response.sendRedirect(
        (redirectParam != null)
        ? (redirectTo
            + "?" + redirectParam
            + "=" + UrlEscapers.urlFormParameterEscaper().escape(
                HttpUtil.getRequestUrl(request, true).toString()))
        : redirectTo);
  }

  private void changeCookieAndRedir(HttpServletRequest request, HttpServletResponse response,
      Cookie cookie, COOKIE_VALUES andThen)
      throws IOException {
    String returnPath = request.getParameter(AuthnMechSampleUrl.DEFAULT_RETURN_URL_PARAMETER);

    // if the returnPath is null, this site was directly accessed (vs. redirected
    // from the security manager) and should just redirect without setting any cookies
    if (Strings.isNullOrEmpty(returnPath)) {
      emitRedirect(request, response, redirectUrl, null);
      return;
    }

    GCookie.addHttpResponseCookie(
        setCookieValue(cookie, andThen.toString()),
        response);
    emitRedirect(request, response, returnPath, null);
  }

  private GCookie setCookieValue(Cookie cookie, String newValue) {
    return makeCookie(cookie.getName(), newValue);
  }

  protected static Cookie findCookie(Cookie[] cookies, String targetName) {
    if (cookies != null) {
      for (Cookie c : cookies) {
        if (c.getName().equalsIgnoreCase(targetName)) {
          return c;
        }
      }
    }
    return null;
  }
}
