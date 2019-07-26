// Copyright 2013 Google Inc.
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

import com.google.common.base.Ticker;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.testing.PortPicker;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import java.net.URL;
import org.mockito.Mockito;

/**
 * Tests for the {@link PageFetcher} class.
 */
public class PageFetcherTest extends SecurityManagerTestCase {
  private static final int SERVER_BACKLOG = 5;
  private static final int SERVER_THREADS = 10;

  private final int port;
  private final TrivialHttpServer httpServer;
  private final HttpClientAdapter httpClient;

  private final Ticker ticker;
  private final SlowHostTracker tracker;
  private final HttpRequester requester;
  private final PageFetcher fetcher;
  private final DenyRulesInterface mockDenyRules;

  private final URL testServerUrl;

  public PageFetcherTest()
      throws IOException {
    port = PortPicker.pickUnusedPort();
    httpServer = new TrivialHttpServer(port, SERVER_BACKLOG, SERVER_THREADS);
    httpServer.start();
    testServerUrl = HttpUtil.urlFromString("http://localhost:" + port + "/");

    mockDenyRules = Mockito.mock(DenyRulesInterface.class);
    httpClient = (HttpClientAdapter) ConfigSingleton.getInstance(HttpClientInterface.class);
    httpClient.setDenyRules(mockDenyRules);

    ticker = Ticker.systemTicker();
    tracker = SlowHostTracker.getInstanceForTesting(ticker);
    fetcher = PageFetcher.getInstanceForTesting(tracker);
    requester = HttpRequester.builder()
        .setPageFetcher(fetcher)
        .build();
  }

  @Override
  public void setUp()
      throws Exception {
    super.setUp();
    httpServer.resetParameters();
    Mockito.when(mockDenyRules.getRule(Mockito.anyString())).thenReturn(null);
  }

  public void testFullGet() throws IOException {
    HttpExchange exchange = httpClient.getExchange(testServerUrl);

    fetcher.fetch(exchange, requester, null);
    assertEquals("GET", exchange.getHttpMethod());
    assertEquals(null, exchange.getRequestHeaderValue(HttpUtil.HTTP_HEADER_RANGE));
  }

  public void testZeroLengthGet() throws IOException {
    HttpExchange exchange = httpClient.getExchange(testServerUrl, 0);

    fetcher.fetch(exchange, requester, null);
    assertEquals("GET", exchange.getHttpMethod());
    assertEquals("bytes=0-0", exchange.getRequestHeaderValue(HttpUtil.HTTP_HEADER_RANGE));
    assertEquals("*/*", exchange.getRequestHeaderValue(HttpUtil.HTTP_HEADER_ACCEPT));
  }

  public void testHeadRequest() throws IOException {
    HttpExchange exchange = httpClient.headExchange(testServerUrl);

    fetcher.fetch(exchange, requester, null);
    assertEquals("HEAD", exchange.getHttpMethod());
  }


}
