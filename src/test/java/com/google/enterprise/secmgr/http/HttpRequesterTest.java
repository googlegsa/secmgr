// Copyright 2018 Google Inc.
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

import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.testing.PortPicker;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import java.net.URL;
import org.mockito.Mockito;

/**
 * Tests for the {@link HttpRequester} class.
 */
public class HttpRequesterTest extends SecurityManagerTestCase {
  private static final int SERVER_BACKLOG = 5;
  private static final int SERVER_THREADS = 10;

  private final int port;
  private final TrivialHttpServer httpServer;
  private final HttpRequester httpRequester;
  private final DenyRulesInterface mockDenyRules;

  private final String permitUrl;
  private final String denyUrl;
  private final String redirectUrl;
  private final HttpClientAdapter httpClient;

  public HttpRequesterTest()
      throws IOException {
    port = PortPicker.pickUnusedPort();
    httpServer = new TrivialHttpServer(port, SERVER_BACKLOG, SERVER_THREADS);
    httpServer.start();
    mockDenyRules = Mockito.mock(DenyRulesInterface.class);
    httpRequester = HttpRequester.builder().setDenyRules(mockDenyRules).build();
    permitUrl = getUrl("");
    denyUrl = getUrl("accessdenied");
    redirectUrl = getUrl("redirect");
    httpClient = (HttpClientAdapter) ConfigSingleton.getInstance(HttpClientInterface.class);
    httpClient.setDenyRules(mockDenyRules);
  }

  private String getUrl(String path) {
    return "http://localhost:" + port + "/" + path;
  }

  @Override
  public void setUp()
      throws Exception {
    super.setUp();
    httpServer.resetParameters();
  }

  public void testAuthzUrlPermits() throws Exception {
    // without deny rule
    HttpExchange exchange = httpClient.getExchange(new URL(permitUrl));
    PageFetcherResult result = httpRequester.runExchangeRedirectAuthorize(exchange, false, null);
    assertEquals(AuthzStatus.PERMIT, result.getAuthzStatus());

    // with deny rule
    Mockito.when(mockDenyRules.getRule(permitUrl)).thenReturn(null);
    exchange = httpClient.getExchange(new URL(permitUrl));
    result = httpRequester.runExchangeRedirectAuthorize(exchange, false, null);
    assertEquals(AuthzStatus.PERMIT, result.getAuthzStatus());
    Mockito.verify(mockDenyRules, Mockito.atLeastOnce()).getRule(permitUrl);
  }

  public void testAuthzUrlContentDeny() throws Exception {
    // without the deny rule    
    HttpExchange exchange = httpClient.getExchange(new URL(denyUrl));
    PageFetcherResult result = httpRequester.runExchangeRedirectAuthorize(exchange, false, null);
    assertEquals(AuthzStatus.PERMIT, result.getAuthzStatus());

    // with the deny rule
    Mockito.when(mockDenyRules.getRule(denyUrl)).
        thenReturn(DenyRule.newBuilder()
            .setRequestType(DenyRule.TYPE.GET).addContent("denyphrase").build());
    exchange = httpClient.getExchange(new URL(denyUrl));
    result = httpRequester.runExchangeRedirectAuthorize(exchange, /*getBody*/false, null);
    assertEquals(AuthzStatus.DENY, result.getAuthzStatus());
    Mockito.verify(mockDenyRules, Mockito.atLeastOnce()).getRule(denyUrl);
  }

  /**
   * tests bug 11820201
   */
  public void testAuthzDenyBeforeRedirects() throws Exception {
    // without the deny rule, the redirect is followed, and result is permitted
    HttpExchange exchange = httpClient.newHttpExchange(new URL(redirectUrl));
    PageFetcherResult result = httpRequester.runExchangeRedirectAuthorize(
        exchange, /*getBody*/false, null);
    assertEquals(AuthzStatus.PERMIT, result.getAuthzStatus());
    assertEquals(200, result.getStatusCode());
    assertEquals(denyUrl, result.getUrl().toString());

    // with the deny rule, stop before the redirect and deny
    Mockito.when(mockDenyRules.getRule(redirectUrl)).thenReturn(
        DenyRule.newBuilder().setRequestType(DenyRule.TYPE.HEAD).addStatusCode(302).build());
    exchange = httpClient.getExchange(new URL(redirectUrl));
    result = httpRequester.runExchangeRedirectAuthorize(exchange, /*getBody*/false, null);
    assertEquals(AuthzStatus.DENY, result.getAuthzStatus());
    assertEquals(302, result.getStatusCode());
    assertEquals(redirectUrl, result.getUrl().toString());
    Mockito.verify(mockDenyRules, Mockito.atLeastOnce()).getRule(redirectUrl);
  }

}
