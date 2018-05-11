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

import com.google.common.annotations.VisibleForTesting;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.sessionmanager.KeyMaterial;
import com.google.enterprise.sessionmanager.SessionManagerInterfaceBase;
import java.io.IOException;
import java.net.URL;
import java.util.Objects;
import java.util.logging.Logger;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;

/**
 * An authenticator that handles Kerberos authentication over HTTP client.
 *
 */
@ThreadSafe
public final class KerberosHttpAuthenticator implements HttpAuthenticator {
  private static final Logger logger = Logger.getLogger(KerberosHttpAuthenticator.class.getName());
  private static final String AUTH_SCHEME = "Negotiate";
  private static final int PREFERENCE_RANK = 3;
  private static final String AT_SIGN = "@";
  private static final String HTTP_SERVICE_PREFIX = "HTTP/";

  @GuardedBy("KerberosHttpAuthenticator.class")
  private static SessionManagerInterfaceBase sessionManager;

  @GuardedBy("this")
  private String domain;

  private KerberosHttpAuthenticator() {
  }

  public static HttpAuthenticator make() {
    return new KerberosHttpAuthenticator();
  }

  @Override
  public boolean isApplicable(PageFetcherResult previousResult) {
    return previousResult.needsHttpAuthentication(AUTH_SCHEME) && kerberosEnabled();
  }

  @Override
  public int getPreferenceRank() {
    return PREFERENCE_RANK;
  }

  @Override
  public PageFetcherResult apply(PageFetcherResult previousResult, HttpRequester requester, URL url,
      boolean getBody)
      throws IOException {
    // Do the Kerberos hand shakes and return the final result.
    // The previous response indicated Kerberos by the time it reached here.
    String serverName = HTTP_SERVICE_PREFIX + url.getHost() + AT_SIGN + getDomain();
    String sessionId = requester.getSessionId();

    String blob = getBlobThroughSessionManager(serverName, sessionId);
    if (blob == null) {
      return previousResult;
    }

    String encodedNegotiate = AUTH_SCHEME + " " + blob;
    logger.info(SessionUtil.logMessage(sessionId,
        "Sending Kerberos Negotiate: " + encodedNegotiate));

    HttpExchange exchange = HttpClientUtil.newHttpExchange(url);
    try {
      exchange.setRequestHeader(HttpUtil.HTTP_HEADER_CONNECTION, HttpUtil.KEEP_ALIVE);
      exchange.setRequestHeader(HttpUtil.HTTP_HEADER_USER_AGENT, HttpUtil.USER_AGENT);
      exchange.setRequestHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, encodedNegotiate);
      return requester.runExchange(exchange, getBody, previousResult);
    } finally {
      exchange.close();
    }
  }

  private synchronized String getDomain() {
    return domain;
  }

  @Override
  public boolean equals(Object object) {
    return (object instanceof KerberosHttpAuthenticator);
  }

  @Override
  public int hashCode() {
    return Objects.hash(AUTH_SCHEME);
  }

  @VisibleForTesting
  public static void setTestSessionManager(SessionManagerInterfaceBase manager) {
    sessionManager = manager;
  }

  private static String getBlobThroughSessionManager(String server, String sessionId) {
    SessionManagerInterfaceBase sessionManager = getSessionManager();
    if (!sessionManager.sessionExists(sessionId)) {
      logger.severe(SessionUtil.logMessage(sessionId, "No such session"));
      return null;
    }
    KeyMaterial token = sessionManager.getKrb5TokenForServer(sessionId, server);
    return (token == null) ? null : token.spnegoBlob();
  }

  /**
   * Gets a reference to the current Session Manager.
   *
   * @return reference to current Session Manager
   */
  private static synchronized SessionManagerInterfaceBase getSessionManager() {
    if (sessionManager == null) {
      sessionManager = SessionUtil.getGsaSessionManager();
    }
    return sessionManager;
  }

  /**
   * Checks if kerberos is enabled. Gets the domain name if it's defined.
   *
   * @return true if kerberos is enable.
   */
  private synchronized boolean kerberosEnabled() {
    String serverName = getSessionManager().getKrb5ServerNameIfEnabled();
    if (serverName == null) {
      return false;
    }

    int at = serverName.lastIndexOf(AT_SIGN);
    if (at < 1 || at == serverName.length() - 1) {
      logger.info("server name without domain: " + serverName);
      return false;
    }
    domain = serverName.substring(at + 1);
    return true;
  }
}
