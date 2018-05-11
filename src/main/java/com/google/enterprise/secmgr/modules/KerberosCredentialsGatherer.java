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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.logmanager.LogClientParameters;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.CredentialsGatherer;
import com.google.enterprise.secmgr.authncontroller.CredentialsGathererElement;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.common.Stringify;
import com.google.enterprise.secmgr.config.AuthnMechKerberos;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.sessionmanager.KerberosId;
import com.google.enterprise.util.HttpUtil;
import com.google.inject.Singleton;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Logger;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.joda.time.DateTimeUtils;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;

/**
 * A credentials gatherer that can gather kerberos credentials.
 * It sends Kerberos-based SPNEGO/GSSAPI negotiation defined by RFC 4559.
 *
 */
@Singleton
@ThreadSafe
public class KerberosCredentialsGatherer implements CredentialsGatherer {
  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());

  private static final DateTimeFormatter ISO8601_FORMAT = ISODateTimeFormat.dateTime();
  private static final Logger logger =
      Logger.getLogger(KerberosCredentialsGatherer.class.getName());

  // Cookie that is sent out to initiate logging out of the GSA:
  private static final String AUTHN_LOGOUT_COOKIE_NAME = "GSA_LOGOUT_COOKIE";
  private static final String AT_SIGN = "@";
  private static final String WWW_AUTHENTICATE = "WWW-Authenticate";
  private static final String AUTH_AUTHORIZATION = "Authorization";
  private static final String AUTH_NEGOTIATE = "Negotiate";
  // AUTH_DOMAIN is defined the same as the frontend
  // AuthNConstants.AUTHN_MECH_BASIC_AUTH_USER_DOMAIN_KEY
  //   = AUTHN_MECH_PREFIX + AuthNMechanisms.BASIC_AUTH.toString() + "_USER_DOMAIN"
  private static final String AUTH_DOMAIN = "AuthN-Mech-BASIC_AUTH_USER_DOMAIN";

  @GuardedBy("this")
  private boolean checkedForDomain;
  @GuardedBy("this")
  private String domain;

  @Inject
  private KerberosCredentialsGatherer() {
    checkedForDomain = false;
    domain = null;
  }

  private synchronized String getDomain() {
    Preconditions.checkNotNull(domain);
    return domain;
  }

  @VisibleForTesting
  synchronized void setDomain(String domain) {
    this.domain = domain;
    this.checkedForDomain = true;
  }

  @VisibleForTesting
  synchronized void clearDomain() {
    this.domain = null;
    this.checkedForDomain = false;
  }

  @Override
  public boolean willHandle(SessionView view) {
    return view.getMechanism() instanceof AuthnMechKerberos
        && view.isIndeterminate()
        && useKerberos(view);
  }

  @Override
  public boolean startGathering(CredentialsGathererElement element, HttpServletRequest request,
      HttpServletResponse response)
      throws IOException {
    SessionView view = element.getSessionView();
    gsaLogger.info(view.getRequestId(), "Gathering Kerberos credentials.");
    resetLogoutCookie(view, response);
    String authHeader = request.getHeader(AUTH_AUTHORIZATION);
    if (authHeader != null && authHeader.contains(AUTH_NEGOTIATE)) {
      // as of b/4203367, IE8 will send the authorization header before receiving challenge.
      logger.info(view.logMessage(
          "Got authorization header before sending the challenge."));
      gsaLogger.info(view.getRequestId(),
          "Got authorization header before sending the challenge.");
      gsaLogger.debug(view.getRequestId(),
          "Headers:\n" + HttpUtil.extractHeaderString(request));
      element.addSessionState(validateResponse(authHeader, view));
      return false;
    }
    respondWithChallenge(response, view);
    return true;
  }

  @Override
  public boolean continueGathering(CredentialsGathererElement element, HttpServletRequest request,
      HttpServletResponse response) {
    SessionView view = element.getSessionView();
    gsaLogger.debug(view.getRequestId(),
        "Headers:\n" + HttpUtil.extractHeaderString(request));
    element.addSessionState(
        validateResponse(request.getHeader(AUTH_AUTHORIZATION), element.getSessionView()));
    return false;
  }

  // Checks if kerberos is enabled.  Gets the domain name if it's defined.
  private synchronized boolean useKerberos(SessionView view) {
    synchronized (this) {
      if (checkedForDomain) {
        return domain != null;
      }
    }
    String serverName = SessionUtil.getGsaSessionManager().getKrb5ServerNameIfEnabled();
    if (serverName == null) {
      logger.info(view.logMessage("Kerberos not enabled"));
      setDomain(null);
      return false;
    }
    int at = serverName.lastIndexOf(AT_SIGN);
    if (at < 1 || at == serverName.length() - 1) {
      logger.warning(view.logMessage("Kerberos server name without domain: %s", serverName));
      setDomain(null);
      return false;
    }
    setDomain(serverName.substring(at + 1));
    return true;
  }

  // Resets logout cookie if there is one.
  private void resetLogoutCookie(SessionView view, HttpServletResponse response) {
    // Check if the user sent in a Logout cookie with his request.
    GCookie logoutCookie = view.getUserAgentCookie(AUTHN_LOGOUT_COOKIE_NAME);
    if (logoutCookie != null) {
      // Here the user has logged out and wants to log in again and be
      // presented with a challenge.
      // At the end of this block, we redirect the user back to AUTHN
      // and we want them to continue with the authentication process
      // by validating their response, so we need to expire the user's
      // logout cookie, so we don't run this block again.
      logger.info(view.logMessage("Got logout cookie."));
      GCookie.addHttpResponseCookie(
          GCookie.builder(AUTHN_LOGOUT_COOKIE_NAME).setExpires(0).build(),
          response);
    }
  }

  // Initializes response with the Kerberos challenge.
  private void respondWithChallenge(HttpServletResponse response, SessionView view)
      throws IOException {
    response.addHeader(WWW_AUTHENTICATE, AUTH_NEGOTIATE);
    logger.info(view.logMessage("Querying Kerberos credentials for realm %s",
            Stringify.object(getDomain())));
    gsaLogger.info(view.getRequestId(),
        "Querying Kerberos credentials for realm: "
        + Stringify.object(getDomain()));
    PrintWriter writer
        = ServletBase.initNormalResponse(response, HttpServletResponse.SC_UNAUTHORIZED);
    try {
      String authnEntryUrl = view.getAuthnEntryUrl().toString();
      // TODO: internationalize this message:
      writer.write("<html><head><meta http-equiv='refresh' content=\"0;URL='");
      writer.write(authnEntryUrl);
      writer.write("'\" /><title>Authorization Required</title></head><body>\n");
      writer.write("<p>Need Kerberos authentication from GSA.</p>\n");
      writer.write("<p>If you see this message, usually it means your browser");
      writer.write(" does not send/have the Kerberos credentials because of your");
      writer.write(" current network environment or browsers settings.</p>\n");
      writer.write("<p>To continue and try other authentication mechanisms, click");
      writer.write(" <a href=\"");
      writer.write(authnEntryUrl);
      writer.write("\">here</a>. Otherwise, contact your administrator for help.</p>\n");
      writer.write("</body></html>\n");
    } finally {
      writer.close();
    }
  }

  // Parses the response to the challenge to extract the identity of the caller.
  private AuthnSessionState validateResponse(String authHeader, SessionView view) {
    String namespace = view.getCredentialGroup().getName();
    // The kerberos Authorization response header has the following format:
    //     Authorization: Negotiate [response]
    if (authHeader == null || !authHeader.contains(AUTH_NEGOTIATE)) {
      return AuthnSessionState.empty();
    }

    String[] tokens = authHeader.split(AUTH_NEGOTIATE + " ", 2);
    if (tokens.length < 2 || tokens[1] == null) {
      return AuthnSessionState.empty();
    }
    authHeader = tokens[1];

    // Note header size as a proxy for windows group membership issues
    gsaLogger.debug(view.getRequestId(),
        "Kerberos authorization header size: " + authHeader.length());

    // As in b/3346998, IE will automatically fall back to NTLM when the site is not trusted
    // during the kerberos authentication. However, the header of the NTLM response from IE
    // share the same header "Negotiate" with kerberos. This only happens for the windows
    // IIS server and there is some vague specification at http://support.microsoft.com/kb/215383.
    // Here we assume that if decoded [response] starts with "NTLM" then this is a NTLM header
    // and stop the kerberos authn process. To make it simple, we just check the first 5 letters
    // of the encoded message, which is TlRMT
    if (authHeader.startsWith("TlRMT")) {
      logger.info(view.logMessage("An NTLM header was received during Kerberos authentication. "
              + "Most likely user's browser is misconfigured (check browser zone settings or if "
              + "hostname in search URL matches SPN) - Aborting the Kerberos authn process."));
      gsaLogger.info(view.getRequestId(), "An NTLM header was received during Kerberos "
              + "authentication. Most likely user's browser is misconfigured (check browser zone "
              + "settings or if hostname in search URL matches SPN) - Aborting the Kerberos authn "
              + "process.");
      return AuthnSessionState.empty();
    }

    String sessionId = view.getSessionId();

    KerberosId kerbId = SessionUtil.getGsaSessionManager()
        .storeKrb5Identity(sessionId, authHeader);
    String id = null;
    if (kerbId != null) {
      id = kerbId.getIdentity();
    }

    if (id == null) {
      // Something went wrong - for example, the ticket was invalid, or
      // out of the right time window, or it was not delegatable.
      // TODO: if it's NTLM repsonse, (this info is not available yet),
      // we need to set INDETERMINATE instead, so that it can fall back to NTLM auth.
      logger.info(view.logMessage("Failed to get identity from Kerberos."));
      return AuthnSessionState.of(view.getAuthority(), Verification.refuted());
    }

    // Identity verified.
    int at = id.lastIndexOf(AT_SIGN);
    if (at < 1 || at == id.length() - 1) {
      logger.info(view.logMessage("No Kerberos domain found."));
      gsaLogger.critical(view.getRequestId(), "No Kerberos domain found.");
      return AuthnSessionState.empty();
    }
    logger.info(view.logMessage("Identity <%s> established using Kerberos.", id));

    String userName = id.substring(0, at);
    String realm = id.substring(at + 1);

    // This domain will be used for authzchecker for head requstor.
    // TODO: replace the session manager and authzchecker functions
    // with a java implementation.
    SessionUtil.getGsaSessionManager().setValue(sessionId, AUTH_DOMAIN, realm);
    // TODO: check if the kerberos response header is set somehow
    // through sessionManager

    long expirationTimeMillis = kerbId.getExpirationInSecs() * 1000;
    if (expirationTimeMillis == 0) {
      logger.warning(view.logMessage("No expiration time received, using default."));
      expirationTimeMillis = view.getConfiguredExpirationTime();
    }

    logger.info(view.logMessage("Kerberos id %s expiration %s",
            id, ISO8601_FORMAT.print(expirationTimeMillis)));

    String idToLog = LogClientParameters.recordUsernames ? id : LogClientParameters.ID_NOT_LOGGED;
    gsaLogger.info(view.getRequestId(), "Identity " + idToLog
        + " established using Kerberos."
        + " Expiration: " + ISO8601_FORMAT.print(expirationTimeMillis));
    if (SecurityManagerUtil.isRemoteBeforeTimeValid(expirationTimeMillis,
            DateTimeUtils.currentTimeMillis())) {
      logger.info(view.logMessage("Kerberos ticket has expired."));
      gsaLogger.info(view.getRequestId(), "Kerberos ticket has expired.");
      // Not refute right away. Instead allow some retries.
      return AuthnSessionState.empty();
    }
    return AuthnSessionState.of(view.getAuthority(),
        Verification.verified(expirationTimeMillis,
            AuthnPrincipal.make(userName, namespace, realm)));
  }
}
