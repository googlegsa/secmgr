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

package com.google.enterprise.secmgr.http;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Sets;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.CookieStore;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HtmlParser;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.common.Stringify;
import com.google.enterprise.secmgr.identity.VerificationStatus;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.net.QuotedPrintableCodec;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletResponse;

/**
 * The result of calling {@link PageFetcher#fetch}.
 * Contains lots of useful information about the response from the exchange.
 */
@Immutable
public class PageFetcherResult {
  private static final Logger logger = Logger.getLogger(PageFetcherResult.class.getName());

  private final URL url;
  private final int statusCode;
  private final String sessionId;
  private final URL redirectUrl;
  private final int redirectCount;
  private final byte[] rawBody;
  private final String charset;
  private final ImmutableListMultimap<String, String> receivedHeaders;
  private final ImmutableList<GCookie> receivedCookies;
  private final ImmutableSet<String> cookieCrackedUsernames;
  private final ImmutableSet<String> cookieCrackedGroups;
  @GuardedBy("this") private ImmutableList<AuthenticateHeader> parsedAuthenticateHeaders;
  @GuardedBy("this") private ImmutableList<AuthenticateHeader> parsedProxyAuthenticateHeaders;
  private final DenyRulesInterface denyRules;

  private String body;

  private PageFetcherResult(URL url, int statusCode, String sessionId, URL redirectUrl,
      int redirectCount, byte[] rawBody, String charset,
      ImmutableListMultimap<String, String> receivedHeaders,
      ImmutableList<GCookie> receivedCookies,
      ImmutableSet<String> cookieCrackedUsernames,
      ImmutableSet<String> cookieCrackedGroups,
      DenyRulesInterface denyRules) {
    this.url = url;
    this.statusCode = statusCode;
    this.sessionId = sessionId;
    this.redirectUrl = redirectUrl;
    this.redirectCount = redirectCount;
    this.rawBody = rawBody;
    this.charset = charset;
    this.receivedHeaders = receivedHeaders;
    this.receivedCookies = receivedCookies;
    this.cookieCrackedUsernames = cookieCrackedUsernames;
    this.cookieCrackedGroups = cookieCrackedGroups;
    this.denyRules = denyRules;
    this.body = null;
  }

  /**
   * Make a new result.
   *
   * @param url The URL that was fetched.
   * @param statusCode The HTTP status code from the response.
   * @param exchange The exchange object to get values from.
   * @param sessionId The session ID to use for log messages.
   * @return A new result with the given contents.
   */
  public static PageFetcherResult make(URL url, int statusCode, HttpExchange exchange,
      String sessionId, DenyRulesInterface denyRules)
      throws IOException {
    Preconditions.checkArgument(statusCode >= 100 && statusCode < 600);
    Preconditions.checkNotNull(exchange);
    // Will be null if not a redirect:
    String redirectUrl = HttpClientUtil.getRedirectUrl(exchange);
    ListMultimap<String, String> responseHeaders = exchange.getResponseHeaders();
    return new PageFetcherResult(
        url,
        statusCode,
        sessionId,
        (redirectUrl == null) ? null : HttpUtil.urlFromString(url, redirectUrl),
        0,
        exchange.getResponseEntityAsByteArray(),
        exchange.getResponseCharSet(),
        ImmutableListMultimap.copyOf(responseHeaders),
        parseHttpResponseCookies(responseHeaders, url, sessionId),
        parseCrackedItems(responseHeaders, HttpUtil.COOKIE_CRACK_USERNAME_HEADER, sessionId),
        parseCrackedItems(responseHeaders, HttpUtil.COOKIE_CRACK_GROUPS_HEADER, sessionId),
        denyRules);
  }

  /**
   * Update a result to reflect that a redirect has been followed.
   *
   * @param redirectUrl The redirect URL, if the response was a redirect.
   * @param redirectCount The number of redirects followed to get the response.
   * @return A (potentially) new result with updated redirect information.
   */
  public PageFetcherResult updateRedirect(URL redirectUrl, int redirectCount) {
    Preconditions.checkArgument(redirectCount >= 0);
    return (HttpUtil.areUrlsEqual(redirectUrl, this.redirectUrl)
        && redirectCount == this.redirectCount)
        ? this
        : new PageFetcherResult(
            url,
            statusCode,
            sessionId,
            (redirectCount == 0) ? null : redirectUrl,
            redirectCount,
            rawBody,
            charset,
            receivedHeaders,
            receivedCookies,
            cookieCrackedUsernames,
            cookieCrackedGroups,
            denyRules);
  }

  public PageFetcherResult merge(PageFetcherResult previousResult) {
    if (previousResult == null) {
      return this;
    }
    return new PageFetcherResult(
        url,
        statusCode,
        sessionId,
        redirectUrl,
        redirectCount,
        rawBody,
        charset,
        receivedHeaders,
        ImmutableList.<GCookie>builder()
        .addAll(previousResult.receivedCookies)
        .addAll(receivedCookies)
        .build(),
        ImmutableSet.copyOf(
            Sets.union(cookieCrackedUsernames, previousResult.cookieCrackedUsernames)),
        ImmutableSet.copyOf(
            Sets.union(cookieCrackedGroups, previousResult.cookieCrackedGroups)),
        denyRules);
  }

  /**
   * @return The URL that was fetched for this page.
   */
  public URL getUrl() {
    return url;
  }

  /**
   * @return The HTTP status code from the response.
   */
  public int getStatusCode() {
    return statusCode;
  }

  /**
   * @return The ID of the session this result is associated with.
   */
  public String getSessionId() {
    return sessionId;
  }

  /**
   * @return The redirect URL, if the response was a redirect, else
   *     {@code null}.
   */
  public URL getRedirectUrl() {
    return redirectUrl;
  }

  /**
   * @return The number of redirects that were followed to get this response.
   */
  public int getRedirectCount() {
    return redirectCount;
  }

  /**
   * @return The body of the response; may be null.
   */
  public String getBody() {
    if (body == null) {
      try {
        body = new String(rawBody, charset);
      } catch (UnsupportedEncodingException exp) {
        logger.warning(SessionUtil.logMessage(sessionId,
                "Unable to convert the body with charset: " + charset));
      }
    }
    return body;
  }

  public byte[] getRawBody() {
    return rawBody;
  }

  /**
   * @return The headers from the response, as an immutable multimap.
   */
  public ListMultimap<String, String> getReceivedHeaders() {
    return receivedHeaders;
  }

  /**
   * @return The cookies sent in the response, as an immutable list.
   */
  public List<GCookie> getReceivedCookies() {
    return receivedCookies;
  }

  /**
   * @return The "cracked" usernames from the response, as an immutable set.
   */
  public Set<String> getCookieCrackedUsernames() {
    return cookieCrackedUsernames;
  }

  /**
   * @return The "cracked" groups from the response, as an immutable set.
   */
  public Set<String> getCookieCrackedGroups() {
    return cookieCrackedGroups;
  }

  /**
   * Get the header values for a given name.
   *
   * @param name The header name to look for.
   * @return The header values as an immutable list.
   */
  public List<String> getHeaderValues(String name) {
    List<String> values = receivedHeaders.get(name.toLowerCase());
    if (values == null) {
      return ImmutableList.of();
    }
    return values;
  }

  /**
   * Get the header values for a given name.
   *
   * @param headers The headers to look in.
   * @param name The header name to look for.
   * @return The header values as an immutable list.
   */
  public static List<String> getHeaderValues(ListMultimap<String, String> headers, String name) {
    List<String> values = headers.get(name.toLowerCase());
    if (values == null) {
      return ImmutableList.of();
    }
    return values;
  }

  /**
   * Get the header value for a given name.  If there are multiple headers,
   * returns the value of the first one.
   *
   * @param name The header name to look for.
   * @return The header value, or null if no such header.
   */
  public String getHeaderValue(String name) {
    List<String> values = getHeaderValues(name);
    return values.isEmpty() ? null : values.get(0);
  }

  private static ImmutableList<GCookie> parseHttpResponseCookies(
      ListMultimap<String, String> headers, URL url, String sessionId) {
    CookieStore store = GCookie.makeStore();
    GCookie.parseResponseHeaders(
        getHeaderValues(headers, HttpUtil.HTTP_HEADER_SET_COOKIE),
        HttpUtil.toUri(url),
        store,
        SessionUtil.getLogDecorator(sessionId));
    return ImmutableList.copyOf(store);
  }

  private static ImmutableSet<String> parseCrackedItems(ListMultimap<String, String> headers,
      String name, String sessionId) {
    ImmutableSet.Builder<String> builder = ImmutableSet.builder();
    for (String value : getHeaderValues(headers, name)) {
      for (String item : CRACKED_VALUE_SPLITTER.split(value)) {
        String decoded = decodeQuotedPrintable(item, sessionId);
        if (decoded != null) {
          builder.add(decoded);
        }
      }
    }
    return builder.build();
  }

  private static final Splitter CRACKED_VALUE_SPLITTER =
      Splitter.on(',').omitEmptyStrings().trimResults();

  /**
   * Decodes an ASCII Quoted Printable encoded string to Unicode.
   *
   * @param value The encoded String.
   * @param sessionId Session ID for log messages.
   * @return a String with the decoded value or in case of decoding problems the initial string.
   */
  private static String decodeQuotedPrintable(String value, String sessionId) {
    try {
      return QP_CODEC.decode(value);
    } catch (DecoderException e) {
      logger.info(SessionUtil.logMessage(sessionId,
              "Unable to decode cracked item " + Stringify.object(value)
              + ", ignoring: " + e.getMessage()));
      return null;
    }
  }

  private static final QuotedPrintableCodec QP_CODEC =
      new QuotedPrintableCodec(UTF_8.name());

  /**
   * Does this result require HTTP authentication using the given scheme?
   *
   * @param authScheme The authentication scheme to test for.
   * @return True only if this result requires HTTP authentication with authScheme.
   */
  public boolean needsHttpAuthentication(String authScheme) {
    return getStatusCode() == HttpServletResponse.SC_UNAUTHORIZED
        && AuthenticateHeader.hasAuthScheme(authScheme, parseAuthenticateHeaders());
  }

  /**
   * Does this result require HTTP proxy authentication using the given scheme?
   *
   * @param authScheme The authentication scheme to test for.
   * @return True only if this result requires HTTP proxy authentication with authScheme.
   */
  public boolean needsHttpProxyAuthentication(String authScheme) {
    return getStatusCode() == HttpServletResponse.SC_PROXY_AUTHENTICATION_REQUIRED
        && AuthenticateHeader.hasAuthScheme(authScheme, parseProxyAuthenticateHeaders());
  }

  /**
   * @return An immutable list of parsed WWW-Authenticate headers.
   */
  public synchronized List<AuthenticateHeader> parseAuthenticateHeaders() {
    if (parsedAuthenticateHeaders == null) {
      parsedAuthenticateHeaders
          = parseAuthenticateHeadersInternal(HttpUtil.HTTP_HEADER_WWW_AUTHENTICATE);
    }
    return parsedAuthenticateHeaders;
  }

  /**
   * @return An immutable list of parsed Proxy-Authenticate headers.
   */
  public synchronized List<AuthenticateHeader> parseProxyAuthenticateHeaders() {
    if (parsedProxyAuthenticateHeaders == null) {
      parsedProxyAuthenticateHeaders
          = parseAuthenticateHeadersInternal(HttpUtil.HTTP_HEADER_WWW_AUTHENTICATE);
    }
    return parsedProxyAuthenticateHeaders;
  }

  private ImmutableList<AuthenticateHeader> parseAuthenticateHeadersInternal(String headerName) {
    ImmutableList.Builder<AuthenticateHeader> builder = ImmutableList.builder();
    for (String headerValue : getHeaderValues(headerName)) {
      try {
        builder.add(AuthenticateHeader.parse(headerValue));
      } catch (IllegalArgumentException e) {
        // Skip any malformed headers.
        logger.info(SessionUtil.logMessage(sessionId, e.getMessage()));
      }
    }
    return builder.build();
  }

  /**
   * Parses the result body as HTML and looks for a form.
   *
   * @return The form element, if any, otherwise {@code null}.
   */
  public Element getForm() {
    try {
      Document document = HtmlParser.parse(getBody());
      NodeList nodes = document.getElementsByTagName(HtmlParser.TAG_FORM);
      return (nodes.getLength() > 0)
          ? (Element) nodes.item(0)
          : null;
    } catch (IOException | DOMException e) {
      logger.info(SessionUtil.logMessage(sessionId,
              "Exception while getting form: " + e.getMessage()));
      return null;
    }
  }

  /**
   * Gets the verification status for this result.  Uses both the HTTP status
   * code and any applicable deny rules.
   */
  public VerificationStatus getVerificationStatus() {
    DenyRule rule = getDenyRule();
    if (rule != null) {
      return evaluateDenyRule(rule) ? VerificationStatus.REFUTED : VerificationStatus.VERIFIED;
    }
    switch (statusCode) {
      case HttpServletResponse.SC_OK:
      case HttpServletResponse.SC_PARTIAL_CONTENT:
        return VerificationStatus.VERIFIED;
      case HttpServletResponse.SC_UNAUTHORIZED:
      case HttpServletResponse.SC_FORBIDDEN:
        return VerificationStatus.REFUTED;
      default:
        return VerificationStatus.INDETERMINATE;
    }
  }

  /**
   * Returns whether or not a deny rule exists for this page.
   *
   * @return true iff a deny rule was found for the current page
   */
  public boolean canApplyDenyRule() {
    return getDenyRule() != null;
  }

  /**
   * Gets the authorization status for this result.  Uses both the HTTP status
   * code and any applicable deny rules.
   */
  public AuthzStatus getAuthzStatus() {
    DenyRule rule = getDenyRule();
    if (rule != null) {
      return evaluateDenyRule(rule) ? AuthzStatus.DENY : AuthzStatus.PERMIT;
    }
    switch (statusCode) {
      case HttpServletResponse.SC_OK:
      case HttpServletResponse.SC_PARTIAL_CONTENT:
        if (getRedirectCount() > 0 && getForm() != null) {
          logger.warning(SessionUtil.logMessage(sessionId,
                  "Redirected to form; interpreting as a DENY: " + url));
          return AuthzStatus.DENY;
        }
        return AuthzStatus.PERMIT;
      case HttpServletResponse.SC_UNAUTHORIZED:
      case HttpServletResponse.SC_FORBIDDEN:
        return AuthzStatus.DENY;
      default:
        return AuthzStatus.INDETERMINATE;
    }
  }

  private DenyRule getDenyRule() {
    return denyRules.getRule(url.toString());
  }

  // Returns true if the deny rule says to deny access.
  private boolean evaluateDenyRule(DenyRule rule) {
    // Check status code, header or content.
    for (int denyStatus : rule.getStatusCodeList()) {
      if (statusCode == denyStatus) {
        return true;
      }
    }
    for (DenyRule.Header header : rule.getHeaderList()) {
      for (String value : getHeaderValues(header.getName())) {
        if (value.toLowerCase().indexOf(header.getValue().toLowerCase()) > -1) {
          return true;
        }
      }
    }
    if (rawBody != null && getBody() != null) {
      for (String denyContent : rule.getContentList()) {
        if (body.indexOf(denyContent) > -1) {
          return true;
        }
      }
    }
    return false;
  }
}
