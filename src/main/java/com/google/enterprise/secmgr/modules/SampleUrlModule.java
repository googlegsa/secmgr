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

import com.google.common.base.Joiner;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.enterprise.secmgr.authncontroller.AuthnModule;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.CookieStore;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HtmlParser;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.IdentityUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.common.Stringify;
import com.google.enterprise.secmgr.config.AuthnMechSampleUrl;
import com.google.enterprise.secmgr.http.HttpRequester;
import com.google.enterprise.secmgr.http.PageFetcherResult;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.inject.Singleton;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.net.URL;
import java.util.Set;
import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * This class provides a simple sample URL checker, and an authentication module
 * that uses the checker.  The checker can extract a username and/or group names
 * from the HTTP headers coming back from the sample URL response.
 *
 * The cookies needed for the sample URL check to pass must already be in the
 * provided session-view object for the check to pass.  Usually the cookies are
 * obtained through inbound cookie forwarding, a credentials gatherer plug-in
 * (such as a redirector), or from a forms-auth module that was run before this
 * one (this is useful when the forms-auth server could not be modified to
 * provide direct cookie cracking, and so a separate "cracking only" server
 * (which is not capable of presenting a form or logging on) is needed.
 *
 */
@Singleton
@Immutable
public final class SampleUrlModule implements AuthnModule {
  private static final Logger logger = Logger.getLogger(SampleUrlModule.class.getName());

  /**
   * A dumb data object holding the results of a sample-URL check.
   */
  public static final class SampleUrlCheckResult {
    private final VerificationStatus status;
    private final PageFetcherResult result;
    private final ImmutableSet<Credential> verifiedCredentials;
    private final boolean isNoCookieResult;

    private SampleUrlCheckResult(VerificationStatus status, PageFetcherResult result,
        Set<Credential> verifiedCredentials, boolean isNoCookieResult) {
      this.status = status;
      this.result = result;
      this.verifiedCredentials = (verifiedCredentials != null)
          ? ImmutableSet.copyOf(verifiedCredentials)
          : ImmutableSet.<Credential>of();
      this.isNoCookieResult = isNoCookieResult;
    }

    public VerificationStatus getVerificationStatus() {
      return status;
    }

    public PageFetcherResult getPageFetcherResult() {
      return result;
    }

    public ImmutableSet<Credential> getVerifiedCredentials() {
      return verifiedCredentials;
    }

    public boolean isNoCookieResult() {
      return isNoCookieResult;
    }
  }

  // -----------------------------------------------------
  // SampleUrlCheck implementation.

  @Inject
  private SampleUrlModule() {
  }

  @Override
  public boolean willHandle(SessionView view) {
    return view.getMechanism() instanceof AuthnMechSampleUrl
        // Else is handled by RedirectCredentialsGatherer:
        && Strings.isNullOrEmpty(((AuthnMechSampleUrl) view.getMechanism()).getRedirectUrl());
  }

  @Override
  public AuthnSessionState authenticate(SessionView view)
      throws IOException {
    SampleUrlCheckResult result = checkSampleUrl(view, false);
    return (result != null)
        ? ModuleUtil.standardAuthnResult(view,
            result.getVerificationStatus(),
            result.getVerifiedCredentials(),
            result.getPageFetcherResult().getReceivedCookies())
        : AuthnSessionState.empty();
  }

  /**
   * Checks a sample URL.
   *
   * @param view A session view to perform the check against,
   * @param getBody If true, retrieve the body of the retrieved URL.
   * @return A compound result.
   * @throws IOException if any I/O errors occur while checking.
   */
  @Nonnull
  static SampleUrlCheckResult checkSampleUrl(SessionView view, boolean getBody)
      throws IOException {
    if (view.getRequest() == null && AuthnSession.isSecureSearchApiMode()) {
      return null;
    }

    PageFetcherResult result = doFetch(view, getBody, false, null);
    if (result == null) {
      return null;
    }

    // Check status first.
    if (!HttpUtil.isGoodHttpStatus(result.getStatusCode())) {
      return new SampleUrlCheckResult(VerificationStatus.REFUTED, result, null, false);
    }

    Set<Credential> credentials = getCrackedCredentials(result, view);
    if (credentials == null) {
      return new SampleUrlCheckResult(VerificationStatus.INDETERMINATE, result, null, false);
    }

    // If cookie cracking worked, we're done.
    if (!credentials.isEmpty()) {
      return new SampleUrlCheckResult(VerificationStatus.VERIFIED, result, credentials, false);
    }

    // check the deny rules
    if (result.getVerificationStatus() == VerificationStatus.REFUTED) {
        return new SampleUrlCheckResult(VerificationStatus.REFUTED, result, null, false);
    }

    // Otherwise, our success requirements are stricter: we must not have seen
    // any redirects, and must have a non- empty body in the result page.
    if (getBody && Strings.isNullOrEmpty(result.getBody())) {
      logger.info(view.logMessage("Sample URL check fails; received empty response."));
      return new SampleUrlCheckResult(VerificationStatus.REFUTED, result, null, false);
    }

    // If there were no redirects, that means we've got valid cookies; we're done.
    if (result.getRedirectCount() == 0) {
      return new SampleUrlCheckResult(VerificationStatus.VERIFIED, result, null, false);
    }

    // Got a redirect.  At this point we don't know if we have good cookies and
    // got a normal redirect, or we have bad cookies and were redirected to the
    // authenticating server.  We'll have to use heuristics.

    // First, if there's a form on the page, we'll assume failure.
    // Also, if the content matches one of the deny rules, we'll assume failure.
    if (getBody) {
      Document document = HtmlParser.parse(result.getBody());
      NodeList nodes = document.getElementsByTagName(HtmlParser.TAG_FORM);
      if (nodes.getLength() > 0) {
        return new SampleUrlCheckResult(VerificationStatus.REFUTED, result, null, false);
      }
    }

    // Otherwise, try again without cookies; if we get the same redirect, then
    // we fail.
    PageFetcherResult result2 = doFetch(view, getBody, true, result);
    if (result2.getRedirectCount() == 0) {
      logger.warning(view.logMessage("No-cookie sample URL check didn't redirect."));
      return new SampleUrlCheckResult(VerificationStatus.INDETERMINATE, result2, null, true);
    }
    if (result.getRedirectUrl().equals(result2.getRedirectUrl()) ||
        (getBody && (result.getBody().equals(result2.getBody())))) {
      logger.info(view.logMessage("Sample URL check fails; got a redirect."));
      return new SampleUrlCheckResult(VerificationStatus.REFUTED, result2, null, true);
    }

    return new SampleUrlCheckResult(VerificationStatus.VERIFIED, result2, null, true);
  }

  /**
   * Fetches a sample URL without analyzing the result.
   *
   * @param view A session view to perform the check against,
   * @param getBody If true, retrieve the body of the retrieved URL.
   * @param noCookies If true, don't send cookies in the request.
   * @param previousResult The result from a previous fetch.
   * @return A compound result, or null if there's no URL to fetch.
   * @throws IOException if any I/O errors occur during the fetch.
   */
  @Nullable
  static PageFetcherResult doFetch(SessionView view, boolean getBody, boolean noCookies,
      PageFetcherResult previousResult)
      throws IOException {
    CookieStore cookieStore = GCookie.makeStore();
    if (view.getRequest() != null) {
      cookieStore = GCookie.parseHttpRequestCookies(view.getRequest(),
          SessionUtil.getLogDecorator(view.getSessionId()));
    }

    String sampleUrlString = view.getMechanism().getSampleUrl();
    if (Strings.isNullOrEmpty(sampleUrlString)) {
      logger.info(view.logMessage("Trying to check an empty sample URL."));
      return null;
    }
    logger.info(view.logMessage("Fetching sample URL%s: %s",
            (noCookies ? " without cookies" : ""),
            HttpUtil.getUrlLogString(sampleUrlString)));

    URL sampleUrl = new URL(sampleUrlString);

    // Try to fetch the sample URL with cookies.
    HttpRequester requester = HttpRequester.builder()
        .setUserAgentCookies(cookieStore.isEmpty() ? view.getUserAgentCookies() : cookieStore)
        .setAuthorityCookies(view.getAuthorityCookies())
        .setSessionId(view.getSessionId())
        .setRequestId(view.getRequestId())
        .setSendCookies(!noCookies)
        .setParamsFromMechanism(view.getMechanism())
        .build();
    PageFetcherResult result = requester.sendGet(sampleUrl, getBody, previousResult);

    logger.info(view.logMessage("Sample URL status code: %s, # redirects = %d",
            result.getStatusCode(),
            result.getRedirectCount()));
    if (!result.getCookieCrackedUsernames().isEmpty()) {
      logger.info(view.logMessage("Sample URL produced cookie-cracked username(s): %s",
              Joiner.on(", ").join(result.getCookieCrackedUsernames())));
    }
    if (!result.getCookieCrackedGroups().isEmpty()) {
      logger.info(view.logMessage("Sample URL produced cookie-cracked group(s): %s",
              Joiner.on(", ").join(result.getCookieCrackedGroups())));
    }

    return result;
  }

  private static Set<Credential> getCrackedCredentials(PageFetcherResult result, SessionView view) {
    ImmutableSet.Builder<Credential> builder = ImmutableSet.builder();

    // If the sample URL check cracked a cookie, then the resulting username
    // becomes the verified principal.  But check first to make sure it
    // matches a previously verified principal.
    Set<String> usernames = result.getCookieCrackedUsernames();
    if (!usernames.isEmpty()) {
      AuthnPrincipal principal = view.getVerifiedPrincipal();
      String namespace = view.getCredentialGroup().getName();
      if (principal == null) {
        builder.add(AuthnPrincipal.parse(Iterables.get(usernames, 0), namespace));
      } else {
        String username
            = IdentityUtil.joinNameDomain(
                principal.getName(),
                principal.getDomain());
        if (!usernames.contains(username)) {
          logger.warning(view.logMessage(
                  "Cracked username %s doesn't match previously verified username %s",
                  Stringify.object(Iterables.get(usernames, 0)),
                  Stringify.object(username)));
          return null;
        }
        builder.add(principal);
      }
    }
    String namespace = view.getCredentialGroup().getName();
    Set<String> groupNames = result.getCookieCrackedGroups();
    if (!groupNames.isEmpty()) {
      ImmutableSet.Builder<Group> groupsBuilder = ImmutableSet.builder();
      for (String groupName : groupNames) {
        String[] tmpGroup = IdentityUtil.parseNameAndDomain(groupName);
        groupsBuilder.add(Group.make(tmpGroup[0], namespace, tmpGroup[1]));
      }
      builder.add(view.extendGroupMemberships(groupsBuilder.build()));
    }

    return builder.build();
  }
}
