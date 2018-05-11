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

package com.google.enterprise.secmgr.http;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.collect.ListMultimap;
import com.google.enterprise.secmgr.common.CookieStore;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;

import java.net.URL;

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;

/**
 * Utilities useful throughout the security manager.
 */
@ThreadSafe
public class HttpClientUtil {

  // don't instantiate
  private HttpClientUtil() {
    throw new UnsupportedOperationException();
  }

  @GuardedBy("HttpClientUtil.class") private static HttpClientInterface httpClient;

  private static synchronized HttpClientInterface getHttpClient() {
    if (httpClient == null) {
      httpClient = ConfigSingleton.getInstance(HttpClientInterface.class);
    }
    return httpClient;
  }

  /**
   * Sets the HTTP client to use when communicating with client servers.  To be
   * used by unit tests to override the default transport mechanism.
   *
   * @param httpClient An HTTP client.
   */
  @VisibleForTesting
  public static synchronized void setHttpClient(HttpClientInterface httpClient) {
    Preconditions.checkNotNull(httpClient);
    HttpClientUtil.httpClient = httpClient;
  }

  /**
   * Resets the HTTP client to the production client.  To be used by unit tests
   * to restore the client after overriding it.
   */
  @VisibleForTesting
  public static synchronized void resetHttpClient() {
    HttpClientUtil.httpClient = ConfigSingleton.getInstance(HttpClientInterface.class);
  }

  /**
   * Creates a new HTTP HEAD exchange object.
   *
   * @param url A URL to send the request to.
   * @return A new HTTP exchange object.
   */
  @Nonnull
  public static HttpExchange headExchange(URL url) {
    return getHttpClient().headExchange(url);
  }

  /**
   * Creates a new HTTP GET exchange object.
   *
   * @param url A URL to send the request to.
   * @return A new HTTP exchange object.
   */
  @Nonnull
  public static HttpExchange getExchange(URL url) {
    return getHttpClient().getExchange(url);
  }

  /**
   * Creates a new HTTP GET exchange object with a fixed range.  This is a
   * convenience method.
   *
   * @param url A URL to send the request to.
   * @param length A byte-length limit for the response.
   * @return A new HTTP exchange object.
   */
  @Nonnull
  public HttpExchange getExchange(URL url, @Nonnegative int length) {
    return getHttpClient().getExchange(url, length);
  }

  @Nonnull
  public static HttpExchange getExchange(HttpClientInterface client, URL url, 
      HttpExchangeContext context) {
    return client.getExchange(url, context);
  }

  /**
   * Creates a new HTTP POST exchange object.
   *
   * @param url A URL to send the request to.
   * @param parameters Some POST parameters, or {@code null} if the caller will
   *     fill in the body.
   * @return A new HTTP exchange object.
   */
  @Nonnull
  public static HttpExchange postExchange(URL url,
      @Nullable ListMultimap<String, String> parameters) {
    return getHttpClient().postExchange(url, parameters);
  }

  /**
   * Creates a new HTTP GET or HEAD exchange object.  The method (GET or HEAD)
   * is determined by the deny-rules configured for the given URL.
   *
   * @param url A URL to send the request to.
   * @return A new HTTP exchange object.
   */
  @Nonnull
  public static HttpExchange newHttpExchange(URL url) {
    return getHttpClient().newHttpExchange(url);
  }

  /**
   * Gets a new disposable, single connection HTTP client.
   * Used to guarantee that a sequence of messages all use the same connection.
   */
  @Nonnull
  public static HttpClientInterface newSingleUseClient() {
    return getHttpClient().newSingleUseInstance();
  }

  /**
   * Return the redirect location of an HTTP response.
   *
   * @param exchange The HTTP exchange object containing the response.
   * @return The URL from a <code>Refresh</code> or <code>Location</code>
   *     header, or null if none such.
   */
  public static String getRedirectUrl(HttpExchange exchange) {
    int status = exchange.getStatusCode();
    if (HttpUtil.isGoodHttpStatus(status)) {
      return HttpClientUtil.getRefreshUrl(exchange);
    }
    if (status >= 300 && status < 400) {
      return exchange.getResponseHeaderValue("Location");
    }
    return null;
  }

  /**
   * Get the relative URL string in Refresh header if exists.
   * @param exchange The HTTP exchange object.
   * @return The relative URL string of Refresh header or null
   *   if none exists
   */
  private static String getRefreshUrl(HttpExchange exchange) {
    String refresh = exchange.getResponseHeaderValue("Refresh");
    if (refresh != null) {
      int pos = refresh.indexOf(';');
      if (pos != -1) {
        // found a semicolon
        String timeToRefresh = refresh.substring(0, pos);
        if ("0".equals(timeToRefresh)) {
          // only follow this if its an immediate refresh (0 seconds)
          pos = refresh.indexOf('=');
          if (pos != -1 && (pos + 1) < refresh.length()) {
            return refresh.substring(pos + 1);
          }
        }
      }
    }
    return null;
  }

  /**
   * Parses cookies from the headers of an HTTP response.
   *
   * @param exchange The exchange to get the response headers from.
   * @param sessionId A session ID to add to log messages.
   * @param store A cookie store to which the parsed cookies will be added.
   */
  public static void parseHttpResponseCookies(HttpExchange exchange, String sessionId,
      CookieStore store) {
    GCookie.parseResponseHeaders(
        exchange.getResponseHeaderValues(HttpUtil.HTTP_HEADER_SET_COOKIE),
        HttpUtil.toUri(exchange.getUrl()),
        store,
        SessionUtil.getLogDecorator(sessionId));
  }
}
