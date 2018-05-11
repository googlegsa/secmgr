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

import com.google.common.base.Predicates;
import com.google.common.collect.Iterables;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.logmanager.LogClientParameters;
import com.google.enterprise.secmgr.authncontroller.AuthnModule;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.config.AuthnMechForm;
import com.google.enterprise.secmgr.http.BasicHttpAuthenticator;
import com.google.enterprise.secmgr.http.HttpAuthenticatorException;
import com.google.enterprise.secmgr.http.HttpRequester;
import com.google.enterprise.secmgr.http.KerberosHttpAuthenticator;
import com.google.enterprise.secmgr.http.PageFetcherResult;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.enterprise.secmgr.modules.SampleUrlModule.SampleUrlCheckResult;
import com.google.inject.Singleton;

import org.w3c.dom.Element;

import java.io.IOException;
import java.net.URL;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * This class implements a Form/Cookie HTTP authentication client
 */
@Singleton
@Immutable
public final class FormModule implements AuthnModule {
  private static final Logger logger = Logger.getLogger(FormModule.class.getName());
  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());

  @Inject
  private FormModule() {
  }

  @Override
  public boolean willHandle(SessionView view) {
    return view.getMechanism() instanceof AuthnMechForm;
  }

  @Override
  public AuthnSessionState authenticate(SessionView view)
    throws IOException {

    // Check if the content is already satisfied, in which case we don't need
    // to go through the forms auth process.
    SampleUrlCheckResult result = SampleUrlModule.checkSampleUrl(view, true);
    if (result == null) {
      return AuthnSessionState.empty();
    }
    VerificationStatus status = result.getVerificationStatus();
    PageFetcherResult pfr = result.getPageFetcherResult();
    switch (status) {
      case VERIFIED:
        // If cookie cracking worked, assume forms auth worked.  Otherwise, if
        // we have a verified principal, or we don't need one, we're done.
        if (Iterables.any(result.getVerifiedCredentials(),
                Predicates.instanceOf(AuthnPrincipal.class))
            || view.hasVerifiedPrincipal()
            || !view.getRequiresPrincipal()) {
          return ModuleUtil.standardAuthnResult(view, status,
              result.getVerifiedCredentials(),
              pfr.getReceivedCookies());
        }
        break;

      case REFUTED:
        break;

      case INDETERMINATE:
        return ModuleUtil.indeterminateAuthnResult(view, pfr.getReceivedCookies());
    }

    if (!view.hasPrincipalAndPassword()) {
      logger.info(view.logMessage("No credentials available, unable to proceed with form auth"));
      return ModuleUtil.indeterminateAuthnResult(view, pfr.getReceivedCookies());
    }

    URL sampleUrl = new URL(view.getMechanism().getSampleUrl());
    String username = view.getUsername();
    String password = view.getPassword();

    Element formElement = pfr.getForm();
    // If we don't have a form and the sample-URL check didn't do a no-cookie
    // fetch, do it now.
    if (formElement == null && !result.isNoCookieResult()) {
      pfr = SampleUrlModule.doFetch(view, true, true, pfr);
      formElement = pfr.getForm();
    }
    // If we still don't have a form, there's nothing further we can do.
    if (formElement == null) {
      logger.warning(view.logMessage("Sample URL didn't redirect to a form: %s", sampleUrl));
      gsaLogger.info(view.getRequestId(), "Sample URL didn't redirect to a form: " + sampleUrl);
      return ModuleUtil.indeterminateAuthnResult(view, pfr.getReceivedCookies());
    }

    String idToLog = LogClientParameters.recordUsernames
        ? username : LogClientParameters.ID_NOT_LOGGED;
    logger.info(view.logMessage("FormAuth trying sample url: %s as user: %s",
            sampleUrl, idToLog));
    gsaLogger.info(view.getRequestId(),
        "Forms Auth: trying sample url: " + sampleUrl + " as user: " + idToLog);

    URL formUrl = pfr.getRedirectUrl();
    HttpRequester requester = HttpRequester.builder()
        .addAuthenticator(BasicHttpAuthenticator.make(username, password))
        .addAuthenticator(KerberosHttpAuthenticator.make())
        .addAuthenticator(FormHttpAuthenticator.make(username, password, formUrl, formElement))
        .setUserAgentCookies(view.getUserAgentCookies())
        .setAuthorityCookies(view.getAuthorityCookies())
        .setSessionId(view.getSessionId())
        .setRequestId(view.getRequestId())
        .setParamsFromMechanism(view.getMechanism())
        .build();

    // The result from SampleUrlCheck already contains the page to be
    // authenticated, so just do the auth without adding another sendGet here.
    PageFetcherResult pfr2;
    try {
      pfr2 = requester.maybeAuthenticate(pfr, sampleUrl, true);
    } catch (HttpAuthenticatorException e) {
      logger.warning(view.logMessage("%s", e.getMessage()));
      return ModuleUtil.indeterminateAuthnResult(view, pfr.getReceivedCookies());
    }
    status = pfr2.getVerificationStatus();
    if (!verifyFetchResult(sampleUrl, formUrl, pfr2, view)) {
      status = VerificationStatus.REFUTED;
    }
    return ModuleUtil.standardAuthnResult(view, status,
        view.getPrincipalAndPassword(),
        pfr2.getReceivedCookies());
  }

  /**
   * This is where we check for things other than the status code -
   * i.e.
   *  - did we receive any new or modified cookies?
   *  - did we just get a 200 at the login form?
   */
  private static boolean verifyFetchResult(URL sampleUrl, URL formUrl, PageFetcherResult result,
      SessionView view) {
    // We can only check to see if we're still at the form, and not whether
    // we've successfully fetched a successful sample url.  This is because
    // some customer deployments (which are arguably broken) have forms that
    // do not redirect you back to the originating URL, so a simple equality
    // check between result.getUrl() and sampleUrl will fail for that case.
    if (HttpUtil.areUrlsEqual(result.getUrl(), formUrl)) {
      logger.info(view.logMessage("Did not get redirected away from login form, failing."));
      return false;
    }
    if (HttpUtil.areUrlsEqual(result.getUrl(), sampleUrl)) {
      if (!haveCookiesChanged(result.getReceivedCookies(), view)) {
        logger.info(view.logMessage(
                "Returned to sample URL without new or changed cookies, failing"));
        return false;
      }
    }
    return true;
  }

  private static boolean haveCookiesChanged(Iterable<GCookie> receivedCookies, SessionView view) {
    Iterable<GCookie> authorityCookies = view.getAuthorityCookies();
    for (GCookie receivedCookie : receivedCookies) {
      if (!receivedCookie.equals(findSameName(receivedCookie, authorityCookies))) {
        return true;
      }
    }
    return false;
  }

  private static GCookie findSameName(GCookie cookie, Iterable<GCookie> cookies) {
    for (GCookie c : cookies) {
      if (cookie.hasSameName(c)) {
        return c;
      }
    }
    return null;
  }
}
