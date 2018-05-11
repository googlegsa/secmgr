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

import com.google.common.base.Strings;
import com.google.common.collect.ListMultimap;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.secmgr.authncontroller.CredentialsGatherer;
import com.google.enterprise.secmgr.authncontroller.CredentialsGathererElement;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.config.AuthnMechSampleUrl;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.enterprise.secmgr.modules.SampleUrlModule.SampleUrlCheckResult;
import com.google.inject.Singleton;

import java.io.IOException;
import java.net.URI;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A credentials gatherer that can redirect the user agent to a specified
 * URL.  Uses the Java-managed session to set a flag indicating an outbound
 * redirect is in progress to avoid redirecting again when the system we
 * redirected to redirects us back.  Tells the system we're redirecting to
 * what address they should return to by adding a CGI/GET param called
 * "returnPath" with the desired return address.
 *
 * The purpose here is that the external system will do something to authenticate
 * the user, then set cookies in the user's browser, and redirect the user
 * back to us.  This is generally used when the external login system cannot be
 * adequately emulated by the built-in universal login form.
 *
 */
@Singleton
@Immutable
public class RedirectCredentialsGatherer implements CredentialsGatherer {
  
  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());

  @Inject
  private RedirectCredentialsGatherer() {
  }

  @Override
  public boolean willHandle(SessionView view) {
    AuthnMechanism mech = view.getMechanism();
    return mech instanceof AuthnMechSampleUrl
        && !Strings.isNullOrEmpty(((AuthnMechSampleUrl) mech).getRedirectUrl())
        && view.isIndeterminate();
  }

  @Override
  public boolean startGathering(CredentialsGathererElement element, HttpServletRequest request,
      HttpServletResponse response)
      throws IOException {
    SessionView view = element.getSessionView();

    // Presatisfaction check - if a Sample URL is specified and the user already
    // has valid credentials for this gatherer, skip the redirect entirely.
    if (checkSampleUrl(element, true)) {
      gsaLogger.info(view.getRequestId(), "User's existing credentials pass"
          + " sample URL check. Skipping redirect credentials gathering.");
      return false;
    }

    // When a redirect connector sends a user out, it sets this flag.  This
    // allows it to detect the "return trip" from a redirect so we don't
    // redirect the user again.  This replaces the previous mechanism of
    // searching for a "LOGIN_REDIRECT=true" param in the request, which has
    // causing problems because it could get bookmarked.  Note that this
    // approach has a weakness that it's a single global setting.  This means
    // that multiple redirect credentials gatherers won't work without paying
    // more attention to this flag.
    synchronized (element) {
      if (element.getPrivateState(Boolean.class) == Boolean.TRUE) {
        element.setPrivateState(null);
        return true;
      }
      // And now set the redirectSent flag so it's detected on the return trip.
      element.setPrivateState(Boolean.TRUE);
    }

    AuthnMechSampleUrl mech = (AuthnMechSampleUrl) view.getMechanism();

    // Otherwise, we should generate an outbound redirect.
    URI returnUri = URI.create(mech.getRedirectUrl());
    String returnUrlParameter = mech.getReturnUrlParameter();

    // If the admin already hard-coded a return path into the redirect URL,
    // then respect that.  Otherwise, we need to add it on.
    ListMultimap<String, String> query = HttpUtil.decodeQueryString(returnUri.getQuery());
    if (!query.containsKey(returnUrlParameter)) {
      query.put(returnUrlParameter, view.getAuthnEntryUrlString());
      returnUri = HttpUtil.replaceUriQuery(returnUri, HttpUtil.encodeQueryString(query));
    }
    
    gsaLogger.info(view.getRequestId(), "Redirecting user to URL: " + returnUri.toString());
    response.sendRedirect(returnUri.toString());
    return true;
  }

  @Override
  public boolean continueGathering(CredentialsGathererElement element, HttpServletRequest request,
      HttpServletResponse response)
      throws IOException {
    // In certain scenarios, this additional check is unnecessary
    // (i.e. if we skipped the redirect in the startGathering method because
    // of pre-existing credentials). But there's no way of knowing that here.
    checkSampleUrl(element, false);   
    return false;
  }

  /**
   * Performs a sample url check and updates credentials accordingly.
   *
   * If done as a presatisfaction check, this method will only update the
   * credentials if the sample url check returned a VERIFIED status.
   */
  private boolean checkSampleUrl(CredentialsGathererElement element,
      boolean isPresatisfactionCheck) throws IOException {
    SessionView view = element.getSessionView();
    if (view.getMechanism().getSampleUrl() != null) {
      SampleUrlCheckResult result = SampleUrlModule.checkSampleUrl(view, isPresatisfactionCheck);
      if (result != null) {
        if (!isPresatisfactionCheck ||
            VerificationStatus.VERIFIED.equals(result.getVerificationStatus())) {
          element.addSessionState(
              ModuleUtil.standardAuthnResult(view,
                  result.getVerificationStatus(),
                  result.getVerifiedCredentials(),
                  result.getPageFetcherResult().getReceivedCookies()));
          return true;
        }
      }
    }
    return false;
  }
}
