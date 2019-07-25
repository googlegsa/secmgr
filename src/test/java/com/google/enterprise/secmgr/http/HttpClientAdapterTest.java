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

import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.http.DenyRule.TYPE;
import com.google.enterprise.secmgr.http.HttpClientAdapter.IdleConnectionMonitorThread;
import com.google.enterprise.secmgr.testing.PortPicker;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.conn.BasicClientConnectionManager;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.mockito.Mockito;

/**
 * Tests for the {@link HttpClientAdapter} class.
 */
public class HttpClientAdapterTest extends SecurityManagerTestCase {
  private static final int SERVER_BACKLOG = 5;
  private static final int SERVER_THREADS = 10;

  // This is effectively infinite compared to the timeouts used by HttpClientAdapter.
  private static final int INFINITE_SLEEP = 30 * 1000;

  private final int port;
  private final TrivialHttpServer httpServer;
  private final HttpClientAdapter httpClient;

  private final DenyRulesInterface mockDenyRules;
  private final ProxyConfInterface mockProxyConf;

  public HttpClientAdapterTest()
      throws IOException {
    port = PortPicker.pickUnusedPort();
    httpServer = new TrivialHttpServer(port, SERVER_BACKLOG, SERVER_THREADS);
    httpServer.start();
    httpClient = (HttpClientAdapter) ConfigSingleton.getInstance(HttpClientInterface.class);
    mockDenyRules = Mockito.mock(DenyRulesInterface.class);
    mockProxyConf = Mockito.mock(ProxyConfInterface.class);
  }

  @Override
  public void setUp()
      throws Exception {
    super.setUp();
    httpServer.resetParameters();
    httpClient.setDenyRules(mockDenyRules);
  }

  public void testNormalUrl() throws IOException {
    HttpExchange exchange = makeTestExchange(port);
    try {
      exchange.exchange();
    } finally {
      exchange.close();
    }
  }

  public void testNoListenerUrl() throws IOException {
    HttpExchange exchange = makeTestExchange(PortPicker.pickUnusedPort());
    try {
      exchange.exchange();
      fail("Normal return from URL without listener");
    } catch (ConnectException e) {
      // pass
    } finally {
      exchange.close();
    }
  }

  public void testNullUrl() throws IOException {
    httpServer.setNullResponse(true);
    HttpExchange exchange = makeTestExchange(port);
    try {
      exchange.exchange();
      fail("Normal return from URL that returns a null response");
    } catch (SocketTimeoutException e) {
      // pass
    } finally {
      exchange.close();
    }
  }

  public void testInfiniteSleepUrl() throws IOException {
    tryTimeout(startTimeoutServer());
  }

  public void testSetTimeoutOne() throws IOException {
    HttpExchange exchange = startTimeoutServer();
    exchange.setTimeout(1);
    tryTimeout(exchange);
  }

  public void testSetTimeoutZero() throws IOException {
    HttpExchange exchange = startTimeoutServer();
    exchange.setTimeout(0);
    tryTimeout(exchange);
  }

  public void testSetTimeoutNegative() throws IOException {
    HttpExchange exchange = startTimeoutServer();
    exchange.setTimeout(-1);
    tryTimeout(exchange);
  }

  private HttpExchange startTimeoutServer() {
    httpServer.setSleepTime(INFINITE_SLEEP);
    return makeTestExchange(port);
  }

  private void tryTimeout(HttpExchange exchange)
      throws IOException {
    try {
      exchange.exchange();
      fail("Normal return from URL whose listener never responds");
    } catch (SocketTimeoutException e) {
      // pass
    } finally {
      exchange.close();
    }
  }

  public void testNewHttpExchange() throws IOException {
    String fullGetRequestUrl = "http://www.fullgetrequestthis.com";
    String headRequestUrl = "http://www.getrequestthis.com";
    String zeroLengthGetRequestUrl = "http://www.zerogetrequestthis.com";
    String tenLengthGetRequestUrl = "http://www.tenlengthgetrequestthis.com";
    String noDenyRuleUrl = "http://www.nullthis.com";

    Mockito.when(mockDenyRules.getRule(fullGetRequestUrl)).
        thenReturn(DenyRule.newBuilder().setRequestType(TYPE.GET).setLength(-1).build());
    Mockito.when(mockDenyRules.getRule(headRequestUrl)).
        thenReturn(DenyRule.newBuilder().setRequestType(TYPE.HEAD).build());
    Mockito.when(mockDenyRules.getRule(zeroLengthGetRequestUrl)).
        thenReturn(DenyRule.newBuilder().setRequestType(TYPE.GET).setLength(0).build());
    Mockito.when(mockDenyRules.getRule(tenLengthGetRequestUrl)).
        thenReturn(DenyRule.newBuilder().setRequestType(TYPE.GET).setLength(10).build());
    Mockito.when(mockDenyRules.getRule(noDenyRuleUrl)).thenReturn(null);

    HttpExchange exchange = httpClient.newHttpExchange(new URL(fullGetRequestUrl));
    assertEquals("GET", exchange.getHttpMethod());
    assertEquals(null, exchange.getRequestHeaderValue(HttpUtil.HTTP_HEADER_RANGE));

    exchange = httpClient.newHttpExchange(new URL(zeroLengthGetRequestUrl));
    assertEquals("GET", exchange.getHttpMethod());
    assertEquals("bytes=0-0", exchange.getRequestHeaderValue(HttpUtil.HTTP_HEADER_RANGE));

    exchange = httpClient.newHttpExchange(new URL(tenLengthGetRequestUrl));
    assertEquals("GET", exchange.getHttpMethod());
    assertEquals("bytes=0-10", exchange.getRequestHeaderValue(HttpUtil.HTTP_HEADER_RANGE));

    exchange = httpClient.newHttpExchange(new URL(headRequestUrl));
    assertEquals("HEAD", exchange.getHttpMethod());
    assertEquals(null, exchange.getRequestHeaderValue(HttpUtil.HTTP_HEADER_RANGE));

    exchange = httpClient.newHttpExchange(new URL(noDenyRuleUrl));
    assertEquals("HEAD", exchange.getHttpMethod());
    assertEquals(null, exchange.getRequestHeaderValue(HttpUtil.HTTP_HEADER_RANGE));

    Mockito.verify(mockDenyRules).getRule(fullGetRequestUrl);
    Mockito.verify(mockDenyRules).getRule(zeroLengthGetRequestUrl);
    Mockito.verify(mockDenyRules).getRule(tenLengthGetRequestUrl);
    Mockito.verify(mockDenyRules).getRule(headRequestUrl);
    Mockito.verify(mockDenyRules).getRule(noDenyRuleUrl);
  }

  public void testPerHostLimiting() throws Exception {
    httpServer.setSleepTime(1000);
    int maxConnections = httpClient.getMaxConnectionsPerHost();
    int repeats = (maxConnections * 3) / 2;
    long startTime = System.currentTimeMillis();
    List<Callable<Long>> callables = Lists.newArrayList();
    for (int i = 0; i < repeats; i += 1) {
      callables.add(new LocalCallable(startTime));
    }
    List<Long> deltas
        = SecurityManagerUtil.runInParallel(
            callables,
            10000,
            SessionUtil.getLogDecorator());

    // All requests should have completed:
    assertEquals(repeats, deltas.size());

    // Count number of requests that completed "immediately":
    int nImmediate = 0;
    for (long delta : deltas) {
      if (delta < 2000) {
        nImmediate += 1;
      }
    }

    // The number of "immediate" requests should be the connection limit.
    assertEquals(maxConnections, nImmediate);
  }

  // Related to fix for b/29172050
  public void testThreadPoolConnectionManagerIsUsedByDefaultConstructor() throws Exception {
    HttpClient httpClientField = (HttpClient) getPrivateField("httpClient").get(httpClient);
    assertTrue(httpClientField.getConnectionManager() instanceof PoolingClientConnectionManager);
  }

  // Related to fix for b/29172050
  public void testIdleConnectionMonitorThreadIsCreatedAndExecuted() throws Exception {
    HttpClientAdapter subject = createNewInstance();

    IdleConnectionMonitorThread monitorThread = (IdleConnectionMonitorThread)
        getPrivateField("idleConnectionMonitor").get(subject);

    // Monitor instance created and started
    assertTrue(monitorThread != null && monitorThread.isRunning());
  }

  // Related to fix for b/29172050
  public void testIdleConnectionMonitorThreadIsShutdownAtObjectDisposalByGC() throws Throwable {
    HttpClientAdapter subject = createNewInstance();

    IdleConnectionMonitorThread monitorThread = (IdleConnectionMonitorThread)
        getPrivateField("idleConnectionMonitor").get(subject);

    // Simulate GC
    subject.finalize();

    // Monitor instance has been shut down
    assertTrue(monitorThread != null && !monitorThread.isRunning());
  }

  // Related to fix for b/29172050
  public void testGetSingleConnectionHttpClientShouldNotCreateIldeConnectionMonitorThread()
      throws Exception {
    HttpClientInterface client = httpClient.newSingleUseInstance();
    assertNull(getPrivateField("idleConnectionMonitor").get(client));
  }

  // Related to fix for b/29172050
  public void testGetSingleConnectionHttpClientShouldUseBasicConnectionManager() throws Exception {
    HttpClientInterface singleClient = httpClient.newSingleUseInstance();
    HttpClient httpClient =
        (HttpClient) getPrivateField("httpClient").get(singleClient);
    assertTrue(httpClient.getConnectionManager() instanceof BasicClientConnectionManager);
  }

  private HttpClientAdapter createNewInstance()
      throws NoSuchMethodException, InstantiationException, IllegalAccessException,
          InvocationTargetException {
    Constructor<HttpClientAdapter> constructor = HttpClientAdapter.class.getDeclaredConstructor(
        DenyRulesInterface.class, ProxyConfInterface.class);
    constructor.setAccessible(true);
    HttpClientAdapter subject = constructor.newInstance(mockDenyRules, mockProxyConf);
    return subject;
  }

  private Field getPrivateField(String fieldName) throws Exception {
    Field field = HttpClientAdapter.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    return field;
  }

  private final class LocalCallable implements Callable<Long> {
    final long startTime;

    LocalCallable(long startTime) {
      this.startTime = startTime;
    }

    @Override
    public Long call()
        throws ExecutionException {
      HttpExchange exchange = makeTestExchange(port);
      long endTime;
      try {
        exchange.setTimeout(5000);
        exchange.exchange();
        endTime = System.currentTimeMillis();
      } catch (IOException e) {
        throw new ExecutionException(e);
      } finally {
        exchange.close();
      }
      return endTime - startTime;
    }
  }

  private HttpExchange makeTestExchange(int port) {
    return httpClient.getExchange(HttpUtil.urlFromString("http://localhost:" + port + "/"));
  }
}

