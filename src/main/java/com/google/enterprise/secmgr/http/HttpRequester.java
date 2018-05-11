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
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableCollection;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ListMultimap;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.common.StringPair;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.FlexAuthzRule;

import java.io.IOException;
import java.net.URL;

import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * A general HTTP request processor.  Knows how to follow redirects, handles
 * cookies, does authentication, etc.  This is the core technology for
 * sample-URL checks and head requests.
 */
@Immutable
public class HttpRequester {
  // The max redirects MUST be more than 5, because we have customers with
  // setups requiring more than 5 redirects.
  // See bugs http://b/issue?id=2078622 and http://b/issue?id=229210 .
  // Currently set to 20 to match Mozilla browsers -
  // http://kb.mozillazine.org/Network.http.redirection-limit
  private static final int DEFAULT_MAX_REDIRECTS = 20;

  private final PageFetcher pageFetcher;
  private final ImmutableCollection<GCookie> userAgentCookies;
  private final ImmutableCollection<GCookie> authorityCookies;
  private final ImmutableList<HttpAuthenticator> authenticators;
  private final ImmutableList<StringPair> additionalHeaders;
  private final int maxRedirects;
  private final String sessionId;
  private final String requestId;
  private final int timeout;
  private final boolean sendCookies;
  private final boolean sendAdditionalHeaders;
  private final DenyRulesInterface denyRules;
  private final HttpAuthenticator basicAuthenticator;

  private HttpRequester(
      PageFetcher pageFetcher,
      ImmutableCollection<GCookie> userAgentCookies,
      ImmutableCollection<GCookie> authorityCookies,
      ImmutableList<HttpAuthenticator> authenticators,
      ImmutableList<StringPair> additionalHeaders,
      int maxRedirects,
      String sessionId,
      String requestId,
      int timeout,
      boolean sendCookies,
      boolean sendAdditionalHeaders,
      DenyRulesInterface denyRules) {
    this.pageFetcher = pageFetcher;
    this.userAgentCookies = userAgentCookies;
    this.authorityCookies = authorityCookies;
    this.authenticators = authenticators;
    this.additionalHeaders = additionalHeaders;
    this.maxRedirects = maxRedirects;
    this.sessionId = sessionId;
    this.requestId = requestId;
    this.timeout = timeout;
    this.sendCookies = sendCookies;
    this.sendAdditionalHeaders = sendAdditionalHeaders;
    this.denyRules = denyRules;
    HttpAuthenticator foundBasic = null;
    for (HttpAuthenticator authenticator : authenticators) {
      if (authenticator instanceof BasicHttpAuthenticator) {
        foundBasic = authenticator;
      }
    }
    this.basicAuthenticator = foundBasic;
  }

  public ImmutableCollection<GCookie> getUserAgentCookies() { return userAgentCookies; }
  public Iterable<GCookie> getAuthorityCookies() { return authorityCookies; }
  public Iterable<HttpAuthenticator> getAuthenticators() { return authenticators; }
  public Iterable<StringPair> getAdditionalHeaders() { return additionalHeaders; }
  public int getMaxRedirects() { return maxRedirects; }
  public String getSessionId() { return sessionId; }
  public String getRequestId() { return requestId; }
  public Decorator getLogDecorator() { return SessionUtil.getLogDecorator(sessionId); }
  public int getTimeout() { return timeout; }
  public boolean getSendCookies() { return sendCookies; }
  public boolean getSendAdditionalHeaders() { return sendAdditionalHeaders; }
  public DenyRulesInterface getDenyRules() { return denyRules; }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * A builder class for HttpRequester instances.
   */
  public static class Builder {
    private PageFetcher pageFetcher;
    private ImmutableCollection<GCookie> userAgentCookies;
    private ImmutableCollection<GCookie> authorityCookies;
    private ImmutableList.Builder<HttpAuthenticator> authenticators;
    private ImmutableList.Builder<StringPair> additionalHeaders;
    private int maxRedirects = DEFAULT_MAX_REDIRECTS;
    private String sessionId;
    private String requestId;
    private int timeout;
    private boolean sendCookies = true;
    private boolean sendAdditionalHeaders = false;
    private DenyRulesInterface denyRules;

    private Builder() {
      pageFetcher = ConfigSingleton.getInstance(PageFetcher.class);
      denyRules = ConfigSingleton.getInstance(DenyRules.class);
      userAgentCookies = ImmutableList.of();
      authorityCookies = ImmutableList.of();
      authenticators = ImmutableList.builder();
      additionalHeaders = ImmutableList.builder();
    }

    @VisibleForTesting
    Builder setPageFetcher(PageFetcher pageFetcher) {
      Preconditions.checkNotNull(pageFetcher);
      this.pageFetcher = pageFetcher;
      return this;
    }

    public Builder setUserAgentCookies(Iterable<GCookie> userAgentCookies) {
      this.userAgentCookies = ImmutableList.copyOf(userAgentCookies);
      return this;
    }

    public Builder setAuthorityCookies(Iterable<GCookie> cookies) {
      this.authorityCookies = ImmutableList.copyOf(cookies);
      return this;
    }

    public Builder addAuthenticator(HttpAuthenticator authenticator) {
      authenticators.add(authenticator);
      return this;
    }

    public Builder addAdditionalHeader(StringPair header) {
      additionalHeaders.add(header);
      return this;
    }

    public Builder setMaxRedirects(int maxRedirects) {
      this.maxRedirects = maxRedirects;
      return this;
    }

    public Builder setSessionId(String sessionId) {
      this.sessionId = sessionId;
      return this;
    }

    public Builder setRequestId(String requestId) {
      this.requestId = requestId;
      return this;
    }

    public Builder setTimeout(int timeout) {
      this.timeout = timeout;
      return this;
    }

    public Builder setParamsFromMechanism(AuthnMechanism mech) {
      if (mech.hasTimeout()) {
        timeout = mech.getTimeout();
      }
      return this;
    }

    public Builder setParamsFromRule(FlexAuthzRule rule) {
      if (rule.hasTimeout()) {
        timeout = rule.getTimeout();
      }
      return this;
    }

    public Builder setSendCookies(boolean sendCookies) {
      this.sendCookies = sendCookies;
      return this;
    }


    public Builder setSendAdditionalHeaders(boolean sendAdditionalHeaders) {
      this.sendAdditionalHeaders = sendAdditionalHeaders;
      return this;
    }

    public Builder setDenyRules(DenyRulesInterface denyRules) {
      this.denyRules = denyRules;
      return this;
    }

    public HttpRequester build() {
      return new HttpRequester(
          pageFetcher,
          userAgentCookies,
          authorityCookies,
          authenticators.build(),
          additionalHeaders.build(),
          maxRedirects,
          sessionId,
          requestId,
          timeout,
          sendCookies,
          sendAdditionalHeaders,
          denyRules);
    }
  }

  /**
   * Send a GET request to a URL, collecting any cookies that come back.
   * Follows redirects until the requester's limit is exceeded.
   *
   * @param urlString The URL string to send the request to.
   * @param getBody whether to get the body
   * @param previousResult The result from a previous request.
   * @return A compound result containing lots of information.
   * @throws IOException if there's a problem running the exchange.
   */
  public PageFetcherResult sendGet(String urlString, boolean getBody,
      PageFetcherResult previousResult)
      throws IOException {
    return sendGet(new URL(urlString), getBody, previousResult);
  }

  /**
   * Send a POST request to a URL, collecting any cookies that come back.
   * Follows redirects until the requester's limit is exceeded.
   *
   * @param urlString The URL string to send the request to.
   * @param parameters The POST parameters to send.
   * @param getBody whether to get the body
   * @param previousResult The result from a previous request.
   * @return A compound result containing lots of information.
   * @throws IOException if there's a problem running the exchange.
   */
  public PageFetcherResult sendPost(String urlString, ListMultimap<String, String> parameters,
      boolean getBody, PageFetcherResult previousResult)
      throws IOException {
    return sendPost(new URL(urlString), parameters, getBody, previousResult);
  }

  /**
   * Send a POST request to a URL, collecting any cookies that come back.
   * Follows redirects until the requester's limit is exceeded.
   *
   * @param url The URL to send the request to.
   * @param parameters The POST parameters to send.
   * @param getBody whether to get the body
   * @param previousResult The result from a previous request.
   * @return A compound result containing lots of information.
   * @throws IOException if there's a problem running the exchange.
   */
  public PageFetcherResult sendPost(URL url, ListMultimap<String, String> parameters,
      boolean getBody, PageFetcherResult previousResult)
      throws IOException {
    HttpExchange exchange = HttpClientUtil.postExchange(url, parameters);
    try {
      PageFetcherResult result = runExchangeWithAuthenticators(exchange, getBody, previousResult);
      if (result.getRedirectUrl() == null) {
        // Not a redirect.
        return result;
      }
      result = sendGet(result.getRedirectUrl(), getBody, result);
      return result.updateRedirect(result.getRedirectUrl(), result.getRedirectCount() + 1);
    } finally {
      exchange.close();
    }
  }

  /**
   * Sends a GET request to a URL, applying authenticators, and collecting any
   * cookies that come back.  Follows redirects until the requester's limit is
   * exceeded.
   *
   * @param url A URL to send the request to.
   * @param getBody Whether to get the body.
   * @param previousResult The result from a previous request.
   * @return A compound result containing lots of information.
   * @throws IOException if there's a problem running the exchange.
   */
  public PageFetcherResult sendGet(URL url, boolean getBody, PageFetcherResult previousResult)
      throws IOException {
    return runExchangeRedirectAuthenticate(HttpClientUtil.getExchange(url), getBody,
        previousResult);
  }

  /**
   * Sends a request to a URL, applying authenticators, and collecting any
   * cookies that come back.  Follows redirects until the requester's limit is
   * exceeded, ignoring deny rules.
   *
   * @param exchange An HTTP exchange to start with.
   * @param getBody Whether to get the body.
   * @param previousResult The result from a previous request.
   * @return A compound result containing lots of information.
   * @throws IOException if there's a problem running the exchange.
   */
  public PageFetcherResult runExchangeRedirectAuthenticate(HttpExchange exchange, boolean getBody,
      PageFetcherResult previousResult) throws IOException {
    return runExchangeRedirectAuthenticate(exchange, getBody, previousResult, false);
  }

  /**
   * Same as above but aggressively checks for deny rule matches, giving them precedence over
   * following redirects.
   */
  public PageFetcherResult runExchangeRedirectAuthorize(HttpExchange exchange, boolean getBody,
      PageFetcherResult previousResult) throws IOException {
    return runExchangeRedirectAuthenticate(exchange, getBody, previousResult, true);
  }

  /**
   * Helper method that does the actual work for
   * runExchangeRedirect[Authenticate/Authorize] methods.
   */
  private PageFetcherResult runExchangeRedirectAuthenticate(HttpExchange exchange, boolean getBody,
      PageFetcherResult previousResult, boolean checkDenyRules)
      throws IOException {
    URL url = exchange.getUrl();
    URL thisUrl = url;
    PageFetcherResult result = previousResult;
    HttpExchange thisExchange = exchange;
    for (int redirectCount = 0; redirectCount < maxRedirects; redirectCount++) {

      try {
        if (basicAuthenticator != null
            && KnownAuthSchemers.getInstance().isKnownBasic(thisExchange.getUrl())) {
          result = basicAuthenticator.apply(result, this, url, getBody);
        } else {
          result = runExchangeWithAuthenticators(thisExchange, getBody, result);
        }
      } finally {
        thisExchange.close();
      }

      if (result.getRedirectUrl() == null || result.getRedirectCount() != 0) {
        // Not a redirect.
        return result.updateRedirect(thisUrl, redirectCount);
      }

      // if checkDenyRules && we find a deny rule match, return immediately so the deny rule
      // may be applied
      if (checkDenyRules && result.canApplyDenyRule()) {
        return result;
      }

      thisUrl = result.getRedirectUrl();
      if (HttpUtil.areUrlsEqual(thisUrl, url)) {
        throw new IOException("HTTP redirect loop detected");
      }
      thisExchange = HttpClientUtil.getExchange(thisUrl);
    }
    throw new IOException("Maximum number of redirects exceeded");
  }

  /**
   * Execute the exchange without the authenticators, and follow redirects if
   * there are any.
   *
   * @param exchange the starting exchange info
   * @param getBody whether to get the body
   * @param previousResult The result from a previous request.
   * @return A compound result containing lots of information.
   * @throws IOException if there's a problem running the exchange.
   */
  PageFetcherResult runExchangeRedirect(HttpExchange exchange, boolean getBody,
      PageFetcherResult previousResult)
      throws IOException {
    URL url = exchange.getUrl();
    URL thisUrl = url;
    PageFetcherResult result = previousResult;
    HttpExchange thisExchange = exchange;
    for (int redirectCount = 0; redirectCount < maxRedirects; redirectCount++) {

      try {
        result = runExchange(thisExchange, getBody, result);
      } finally {
        thisExchange.close();
      }

      if (result.getRedirectUrl() == null) {
        // Not a redirect.
        return result.updateRedirect(thisUrl, redirectCount);
      }
      thisUrl = result.getRedirectUrl();
      if (HttpUtil.areUrlsEqual(thisUrl, url)) {
        throw new IOException("HTTP redirect loop detected");
      }
      thisExchange = HttpClientUtil.newHttpExchange(thisUrl);
    }
    throw new IOException("Maximum number of redirects exceeded");
  }

  /**
   * Fetches the url using HEAD or GET based on configuration.
   * Follows redirects until the requester's limit is exceeded.
   *
   * @param url The URL to send the request to.
   * @return A compound result containing lots of information.
   * @throws IOException if there is a problem running the exchange.
   */
  public PageFetcherResult fetch(URL url)
      throws IOException {
    return fetch(url, null);
  }

  /**
   * Fetches the url using HEAD or GET based on configuration.
   * Follows redirects until the requester's limit is exceeded.
   *
   * @param url The URL to send the request to.
   * @param previousResult The result from a previous request.
   * @return A compound result containing lots of information.
   * @throws IOException if there is a problem running the exchange.
   */
  public PageFetcherResult fetch(URL url, PageFetcherResult previousResult)
      throws IOException {
    URL thisUrl = url;
    PageFetcherResult result = previousResult;
    for (int redirectCount = 0; redirectCount < maxRedirects; redirectCount++) {

      result = runExchange(thisUrl, result);
      result = maybeAuthenticate(result, thisUrl, true);

      if (result.getRedirectUrl() == null) {
        // Not a redirect.
        return result.updateRedirect(thisUrl, redirectCount);
      }
      thisUrl = result.getRedirectUrl();

      if (HttpUtil.areUrlsEqual(thisUrl, url)) {
        throw new IOException("HTTP redirect loop detected");
      }
    }
    throw new IOException("Maximum number of redirects exceeded");
  }

  // A bridge to translate between what the above methods need and what
  // FetchPage provides.
  // Do not follow redirects. Do authentication.
  private PageFetcherResult runExchangeWithAuthenticators(HttpExchange exchange, boolean getBody,
      PageFetcherResult previousResult)
      throws IOException {
    PageFetcherResult result = runExchange(exchange, getBody, previousResult);
    return maybeAuthenticate(result, exchange.getUrl(), getBody);
  }

  // Search the available authenticators and choose the highest-ranked
  // applicable one.  If none are found, return the given result.  Otherwise,
  // apply the chosen authenticator and return its result.
  public PageFetcherResult maybeAuthenticate(PageFetcherResult result, URL url, boolean getBody)
      throws IOException {
    HttpAuthenticator preferred = null;
    for (HttpAuthenticator authenticator : authenticators) {
      if (authenticator.isApplicable(result)
          && (preferred == null
              || authenticator.getPreferenceRank() > preferred.getPreferenceRank())) {
        preferred = authenticator;
      }
    }
    return (preferred != null)
        ? preferred.apply(result, this, url, getBody)
        : result;
    // TODO If one is indeterminate, try the next applicable one.
    // check if the result is merged.
  }

  /**
   * Does the exchange for the request. Doesn't follow redirect.
   * Merges the result.
   */
  PageFetcherResult runExchange(HttpExchange exchange, boolean getBody,
      PageFetcherResult previousResult)
      throws IOException {
    // This is tricky. If getBody is true, it doesn't mean we always get the
    // body since the exchange header may have already been set to something
    // else.  This is only to enforce an empty range if it's not been set yet.
    if (!getBody) {
      int contentLen = getDenyruleLength(exchange.getUrl().toString());
      if (contentLen >= 0) {
        exchange.setRequestHeader("Range", "bytes=0-" + contentLen);
      }
    }
    return pageFetcher.fetch(exchange, this, previousResult);
  }

  private int getDenyruleLength(String urlString) {
    DenyRule rule = denyRules.getRule(urlString);
    if (rule == null) {
      return 0;
    } else {
      return rule.getLength();
    }
  }

  /**
   * Fetches a URL using the requester and based on previous result.
   * If it's the first trying to fetch, the previousResult can be null.
   * Doesn't follow redirect. Merges the result.
   */
  PageFetcherResult runExchange(URL url, @Nullable PageFetcherResult previousResult)
      throws IOException {
    return pageFetcher.fetch(url, this, previousResult);
  }
}
