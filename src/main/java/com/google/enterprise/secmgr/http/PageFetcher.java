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
import com.google.enterprise.secmgr.common.CookieStore;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.common.StringPair;
import com.google.inject.Singleton;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.URL;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * The lowest-level page fetching machinery.  This class knows how to do HTTP
 * HEAD, GET, and POST, returning a {@link PageFetcherResult}.
 */
@Immutable
@Singleton
final class PageFetcher {
  private static final Logger logger = Logger.getLogger(PageFetcher.class.getName());

  private final SlowHostTracker slowHostTracker;

  @Inject
  private PageFetcher(SlowHostTracker slowHostTracker) {
    this.slowHostTracker = slowHostTracker;
  }

  @VisibleForTesting
  static PageFetcher getInstanceForTesting(SlowHostTracker slowHostTracker) {
    Preconditions.checkNotNull(slowHostTracker);
    return new PageFetcher(slowHostTracker);
  }

  /**
   * Fetches a page, using POST, GET or HEAD, and does not follow redirects.
   *
   * @param url The URL to fetch.
   * @param requester An HTTP requester containing fetch parameters.
   * @param previousResult The result from a previous request.
   * @return A compound result containing lots of information.
   * @throws IOException if there's a problem running the exchange.
   */
  PageFetcherResult fetch(URL url, HttpRequester requester, PageFetcherResult previousResult)
      throws IOException {
    HttpExchange exchange = HttpClientUtil.newHttpExchange(url);
    try {
      return fetch(exchange, requester, previousResult);
    } finally {
      exchange.close();
    }
  }

  /**
   * Fetches a page, using POST, GET or HEAD, and does not follow redirects.
   *
   * @param exchange An HTTP exchange to use for the fetch.
   * @param requester An HTTP requester containing fetch parameters.
   * @param previousResult The result from a previous request.
   * @return A compound result containing lots of information.
   * @throws IOException if there's a problem running the exchange.
   */
  PageFetcherResult fetch(HttpExchange exchange, HttpRequester requester,
      PageFetcherResult previousResult)
      throws IOException {
    URL url = exchange.getUrl();
    slowHostTracker.checkHost(url.getHost());

    try {
      boolean isHeadRequest = false;
      String method = exchange.getHttpMethod();
      if (HttpUtil.HTTP_METHOD_HEAD.equals(method)) {
        isHeadRequest = true;
      } else if (HttpUtil.HTTP_METHOD_GET.equals(method)) {
        String rangeStr = exchange.getRequestHeaderValue(HttpUtil.HTTP_HEADER_RANGE);
        if (rangeStr != null && rangeStr.equals("bytes=0-0")) {
          isHeadRequest = true;
        }
      }

      for (StringPair sp : HttpUtil.getBoilerplateHeaders(isHeadRequest)) {
        exchange.setRequestHeader(sp.getName(), sp.getValue());
      }

      if (requester.getSendAdditionalHeaders()) {
        for (StringPair sp : requester.getAdditionalHeaders()) {
          exchange.setRequestHeader(sp.getName(), sp.getValue());
        }
      }

      if (requester.getSendCookies()) {
        CookieStore cookiesToSend
            = GCookie.computeCookiesToSend(HttpUtil.toUri(url),
                requester.getUserAgentCookies(),
                (previousResult == null)
                ? requester.getAuthorityCookies()
                : GCookie.mergeCookies(
                    requester.getAuthorityCookies(),
                    previousResult.getReceivedCookies()));
        exchange.addCookies(cookiesToSend);
        logger.info(logMessage(requester,
            GCookie.requestCookiesMessage("Cookies sent to " + HttpUtil.getUrlLogString(url),
                cookiesToSend)));
      }

      exchange.setTimeout(requester.getTimeout());

      int status = exchange.exchange();
      PageFetcherResult result = PageFetcherResult.make(
          url, status, exchange, requester.getSessionId(), requester.getDenyRules());

      logger.info(logMessage(requester,
          GCookie.responseCookiesMessage("Cookies received from " + HttpUtil.getUrlLogString(url),
              result.getReceivedCookies())));

      return result.merge(previousResult);

    } catch (InterruptedIOException e) {
      slowHostTracker.recordHostTimeout(url.getHost());
      throw e;
    }
  }

  private static String logMessage(HttpRequester requester, String message) {
    return SessionUtil.logMessage(requester.getSessionId(), message);
  }
}
