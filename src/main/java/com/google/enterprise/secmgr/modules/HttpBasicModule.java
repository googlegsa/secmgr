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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.CharMatcher;
import com.google.common.collect.ImmutableList;
import com.google.common.net.HttpHeaders;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.logmanager.LogClientParameters;
import com.google.enterprise.secmgr.authncontroller.AuthnModule;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.Base64;
import com.google.enterprise.secmgr.common.Base64DecoderException;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.config.AuthnMechBasic;
import com.google.enterprise.secmgr.http.BasicHttpAuthenticator;
import com.google.enterprise.secmgr.http.DenyRules;
import com.google.enterprise.secmgr.http.HttpRequester;
import com.google.enterprise.secmgr.http.HttpRequester.Builder;
import com.google.enterprise.secmgr.http.PageFetcherResult;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.inject.Singleton;

import java.io.IOException;
import java.net.URL;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 * A module implementing HTTP BASIC authentication.
 */
@Singleton
@Immutable
public final class HttpBasicModule implements AuthnModule {

  private static final Logger logger = Logger.getLogger(HttpBasicModule.class.getName());
  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());

  private final DenyRules denyRules;

  @Inject
  private HttpBasicModule() {
    denyRules = null;
  }

  @VisibleForTesting
  HttpBasicModule(DenyRules denyRules) {
    this.denyRules = denyRules;
  }

  @Override
  public boolean willHandle(SessionView view) {
    return view.getMechanism() instanceof AuthnMechBasic;
  }

  private static String stripPrefix(String str, String prefix) {
    return str.startsWith(prefix) ? str.substring(prefix.length()) : null;
  }

  @Override
  public AuthnSessionState authenticate(SessionView view)
      throws IOException {
    HttpServletRequest request = view.getRequest();
    if (request == null && AuthnSession.isSecureSearchApiMode()) {
      return AuthnSessionState.empty();
    }

    String username = null;
    String password = null;
    String domain = null;

    if (request != null) {
      String domainSlashUsername;

      String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
      if (authHeader != null) {
        authHeader = CharMatcher.whitespace().trimFrom(authHeader);
        authHeader = stripPrefix(authHeader , AuthnMechBasic.SCHEME_NAME);
      }

      if (authHeader != null) {
        try {
          authHeader = new String(Base64.decode(
              CharMatcher.whitespace().trimFrom(authHeader)));
          int colon = authHeader.indexOf(':');

          if (colon > 0) {
            int slash = CharMatcher.anyOf("\\/").indexIn(authHeader);
            if (slash != -1 && slash < colon) {
              domain = authHeader.substring(0, slash);
              username = authHeader.substring(slash + 1, colon);
              domainSlashUsername = domain + "/" + username;
            } else {
              domain = "";
              username = domainSlashUsername = authHeader.substring(0, colon);
            }

            password = authHeader.substring(colon + 1);
          }
        } catch (Base64DecoderException e1) {
          logger.info(view.logMessage("No user/pwd from request"));
          // follow through to try to get user/pwd from view.
        } catch (IllegalArgumentException e2) {
          logger.info(view.logMessage("No user/pwd from request"));
          // follow through to try to get user/pwd from view.
        }
      }
    }

    String sampleUrl = view.getMechanism().getSampleUrl();
    if (username == null) {
      username = view.getUsername();
      if (username == null) {
        return AuthnSessionState.empty();
      }
    }

    String idToLog = LogClientParameters.recordUsernames
        ? username : LogClientParameters.ID_NOT_LOGGED;
    logger.info(view.logMessage("Trying sample url: %s as user: %s",
        HttpUtil.getUrlLogString(sampleUrl), idToLog));

    gsaLogger.info(view.getRequestId(), "Http Basic Auth: Trying sample url: "
        + HttpUtil.getUrlLogString(sampleUrl) + " as user: " + idToLog);

    if (domain == null) {
      domain = view.getDomain();
    }

    if (password == null) {
      password = view.getPassword();
    }

    if (password == null) {
      return AuthnSessionState.empty();
    }

    // This makes the testing of parameters passed in hard to test.
    Builder requesterBuilder = HttpRequester.builder()
        .addAuthenticator(BasicHttpAuthenticator.make(username, password))
        .setParamsFromMechanism(view.getMechanism())
        .setSessionId(view.getSessionId())
        .setRequestId(view.getRequestId());
    if (denyRules != null) {
      requesterBuilder.setDenyRules(denyRules);
    }
    HttpRequester requester = requesterBuilder.build();

    PageFetcherResult result = requester.fetch(new URL(sampleUrl));
    VerificationStatus status = result.getVerificationStatus();
    logger.info(view.logMessage("Sample url: %s user: %s status: %s",
        HttpUtil.getUrlLogString(sampleUrl), username, status));

    AuthnPrincipal principal = AuthnPrincipal.make(username, view.getCredentialGroup().getName(),
        domain);
    CredPassword credPassword = CredPassword.make(password);

    return ModuleUtil.standardAuthnResult(view, status,
        ImmutableList.<Credential>of(principal, credPassword),
        result.getReceivedCookies());
  }
}
