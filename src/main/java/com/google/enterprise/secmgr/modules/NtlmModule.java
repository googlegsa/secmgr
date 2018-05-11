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

import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.logmanager.LogClientParameters;
import com.google.enterprise.secmgr.authncontroller.AuthnModule;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.config.AuthnMechNtlm;
import com.google.enterprise.secmgr.http.HttpRequester;
import com.google.enterprise.secmgr.http.NtlmHttpAuthenticator;
import com.google.enterprise.secmgr.http.PageFetcherResult;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.inject.Singleton;

import java.io.IOException;
import java.net.URL;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * This class implements a NTLM HTTP authentication client.
 *
 */
@Singleton
@Immutable
public class NtlmModule implements AuthnModule {
  private static final Logger logger = Logger.getLogger(NtlmModule.class.getName());
  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());

  @Inject
  private NtlmModule() {
  }

  @Override
  public boolean willHandle(SessionView view) {
    return view.getMechanism() instanceof AuthnMechNtlm;
  }

  @Override
  public AuthnSessionState authenticate(SessionView view)
      throws IOException {

    String sampleUrl = view.getMechanism().getSampleUrl();
    String username = view.getUsername();
    String domain = view.getDomain();
    String password = view.getPassword();

    String idToLog = LogClientParameters.recordUsernames
        ? username : LogClientParameters.ID_NOT_LOGGED;
    logger.info(view.logMessage("Trying sample url: %s as user: %s",
            HttpUtil.getUrlLogString(sampleUrl), idToLog));
    gsaLogger.info(view.getRequestId(), "NTLM Auth: trying sample url: "
        + HttpUtil.getUrlLogString(sampleUrl) + " as user: " + idToLog);

    HttpRequester.Builder builder = HttpRequester.builder()
        .setParamsFromMechanism(view.getMechanism())
        .setSessionId(view.getSessionId())
        .setRequestId(view.getRequestId());
    String urlToFetch;
    builder.addAuthenticator(NtlmHttpAuthenticator.make(domain, username, password));
    urlToFetch = sampleUrl;

    PageFetcherResult result = builder.build().fetch(new URL(urlToFetch));
    // NB: Use sampleUrl here, NOT urlToFetch.  URL is used to find deny rules.
    VerificationStatus status = result.getVerificationStatus();
    logger.info(view.logMessage("Sample url: %s user: %s status: %s",
            HttpUtil.getUrlLogString(sampleUrl), username, status));
    return ModuleUtil.standardAuthnResult(view, status,
        view.getPrincipalAndPassword(),
        result.getReceivedCookies());
  }
}
