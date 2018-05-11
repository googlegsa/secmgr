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

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.enterprise.secmgr.http.BasicHttpAuthenticator;
import com.google.enterprise.secmgr.http.HttpAuthenticatorException;
import com.google.enterprise.secmgr.http.HttpClientUtil;
import com.google.enterprise.secmgr.http.HttpRequester;
import com.google.enterprise.secmgr.http.KerberosHttpAuthenticator;
import com.google.enterprise.secmgr.http.NtlmHttpAuthenticator;
import com.google.enterprise.secmgr.http.PageFetcherResult;
import com.google.enterprise.secmgr.http.SlowHostTracker.UnresponsiveHostException;
import com.google.inject.Singleton;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.SocketException;
import java.net.URL;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * A connector to check a user's access to a URL by sending an HTTP request to
 * the content server with appropriate credentials, handling the authenticate
 * mechanisms supported by the content server accordingly.
 *
 */
@Singleton
@Immutable
public final class HttpRequestModule implements AuthzModule {
  private static final Logger logger = Logger.getLogger(HttpRequestModule.class.getName());
  private static final long REQUEST_TIMEOUT = 5000; // milliseconds

  @Inject
  private HttpRequestModule() {
  }

  @Override
  public AuthzResult authorize(Collection<Resource> resources, SessionView view, FlexAuthzRule rule)
      throws MalformedURLException {

    Collection<String> urls = Resource.resourcesToUrls(resources);
    List<Callable<Map.Entry<String, AuthzStatus>>> callables = makeCallables(urls, view, rule);
    long timeoutMillis = rule.hasTimeout() ? rule.getTimeout() : REQUEST_TIMEOUT;
    try {
      List<Map.Entry<String, AuthzStatus>> entries
          = SecurityManagerUtil.runInParallel(callables, timeoutMillis, view.getLogDecorator());

      AuthzResult.Builder resultsBuilder = AuthzResult.builder(urls);
      for (Map.Entry<String, AuthzStatus> entry : entries) {
        resultsBuilder.add(entry);
      }
      return resultsBuilder.build();
    } catch (ExecutionException e) {
      logger.log(Level.WARNING, view.getLogDecorator().apply("Exception in worker thread: "), 
          e.getCause());
    }
    return AuthzResult.makeIndeterminate(urls);    
  }

  private static List<Callable<Map.Entry<String, AuthzStatus>>> makeCallables(
      Collection<String> urls, SessionView view, FlexAuthzRule rule)
      throws MalformedURLException {
    ImmutableList.Builder<Callable<Map.Entry<String, AuthzStatus>>> builder
        = ImmutableList.builder();
    for (String url : urls) {
      builder.add(new LocalCallable(new URL(url), view, makeRequester(view, rule)));
    }
    return builder.build();
  }

  private static final class LocalCallable implements Callable<Map.Entry<String, AuthzStatus>> {
    private final URL url;
    private final SessionView view;
    private final HttpRequester requester;

    public LocalCallable(URL url, SessionView view, HttpRequester requester) {
      this.url = url;
      this.view = view;
      this.requester = requester;
    }

    @Override
    public Map.Entry<String, AuthzStatus> call()
        throws ExecutionException {
      try {
        return Maps.immutableEntry(url.toString(), doFetch(url, view, requester));
      } catch (IOException e) {
        throw new ExecutionException(e);
      }
    }

    @Override
    public String toString() {
      return LocalCallable.class.getCanonicalName() + "(" + url + ")";
    }
  }

  /**
   * Creates an HTTP requester for a given view with all qualifying authenticators.
   *
   * @param view A session view to use.
   * @return An HTTP requester with appropriate authenticators.
   */
  private static HttpRequester makeRequester(SessionView view, FlexAuthzRule rule) {
    String username = view.getUsername();
    String password = view.getPassword();
    HttpRequester.Builder builder = HttpRequester.builder();
    if (!Strings.isNullOrEmpty(username) && !Strings.isNullOrEmpty(password)) {
      builder
          .addAuthenticator(BasicHttpAuthenticator.make(username, password))
          .addAuthenticator(NtlmHttpAuthenticator.make(view.getDomain(), username, password));
    }
    builder.addAuthenticator(KerberosHttpAuthenticator.make());
    return builder.setSessionId(view.getSessionId())
        .setRequestId(view.getRequestId())
        .setUserAgentCookies(view.getUserAgentCookies())
        .setAuthorityCookies(view.getAuthorityCookies())
        .setParamsFromRule(rule)
        .build();
  }

  private static AuthzStatus doFetch(URL url, SessionView view, HttpRequester requester)
      throws IOException {
    try {
      PageFetcherResult result = requester.runExchangeRedirectAuthorize(
          HttpClientUtil.newHttpExchange(url),
          /*getBody=*/false,
          /*previousResult=*/null);
      return result.getAuthzStatus();
    } catch (HttpAuthenticatorException e) {
      logger.warning(view.logMessage("%s", e.getMessage()));
      return AuthzStatus.INDETERMINATE;
    } catch (UnresponsiveHostException e) {
      logger.warning(view.logMessage("%s", e.getMessage()));
      return AuthzStatus.INDETERMINATE;
    } catch (SocketException e) {
      logger.warning(view.logMessage("%s", e.getMessage()));
      return AuthzStatus.INDETERMINATE;
    }
  }
}

