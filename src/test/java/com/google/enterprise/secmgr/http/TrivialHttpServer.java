/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.enterprise.secmgr.http;

import com.google.common.base.Preconditions;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.ServletBase;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.concurrent.Executors;
import java.util.logging.Logger;

import javax.annotation.Nonnegative;
import javax.annotation.concurrent.GuardedBy;

/**
 * A simple multi-threaded HTTP server to use when testing the HttpClientAdapter.
 */
public final class TrivialHttpServer {
  private static final Logger logger = Logger.getLogger(TrivialHttpServer.class.getName());
  private static final String HEALTHZ = "/healthz";

  private final HttpServer server;
  @GuardedBy("this") @Nonnegative private int sleepTime;
  @GuardedBy("this") private boolean nullResponse;

  /**
   * Creates a new HTTP server.
   *
   * @param port A port to listen on.
   * @param backlog How large a backlog to support; see
   *     {@link HttpServer#create}.
   * @param threadPoolSize How large a thread pool to use; see
   *     {@link Executors#newFixedThreadPool}.
   */
  public TrivialHttpServer(int port, int backlog, int threadPoolSize)
      throws IOException {
    server = HttpServer.create(new InetSocketAddress(InetAddress.getByName(null), port), backlog);
    server.createContext("/", new LocalHandler());
    server.createContext("/redirect", new RedirectHandler());
    server.createContext("/accessdenied", new AccessDeniedPageHandler());
    server.setExecutor(Executors.newFixedThreadPool(threadPoolSize));
    sleepTime = 0;
    nullResponse = false;
  }

  /** @see HttpServer#start */
  public void start() {
    server.start();
  }

  /** @see HttpServer#stop */
  public void stop(int delay) {
    server.stop(delay);
  }

  /**
   * Resets all parameters that control behavior of the server.  Undoes the
   * effects of {@link #setNullResponse} and {@link #setSleepTime}.
   */
  public synchronized void resetParameters() {
    sleepTime = 0;
    nullResponse = false;
  }

  /**
   * Changes the server so that it responds with an empty message.  Does not
   * affect /healthz requests.
   *
   * @param nullResponse If true, the server will respond with an empty message,
   *     otherwise it responds with a normal HTTP message.
   */
  public synchronized void setNullResponse(boolean nullResponse) {
    this.nullResponse = nullResponse;
  }

  private synchronized boolean getNullResponse() {
    return nullResponse;
  }

  /**
   * Changes the server so that it waits for a given number of milliseconds
   * before responding.  Does not affect /healthz requests.
   *
   * @param sleepTime The number of milliseconds to wait.
   */
  public synchronized void setSleepTime(@Nonnegative int sleepTime) {
    Preconditions.checkArgument(sleepTime >= 0);
    this.sleepTime = sleepTime;
  }

  private synchronized int getSleepTime() {
    return sleepTime;
  }

  private final class LocalHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange)
        throws IOException {
      URI uri = exchange.getRequestURI();
      if (!HEALTHZ.equals(uri.getPath())) {
        int t = getSleepTime();
        if (t > 0) {
          try {
            Thread.sleep(t);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
          }
        }
        if (getNullResponse()) {
          logger.info("Null response: " + uri);
          return;
        }
      }
      logger.info("Normal response: " + uri);
      Headers responseHeaders = exchange.getResponseHeaders();
      responseHeaders.add(HttpUtil.HTTP_HEADER_DATE, ServletBase.httpDateString());
      exchange.sendResponseHeaders(200, 0);
      exchange.getResponseBody().close();
    }
  }

  private final class RedirectHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange)
        throws IOException {
      URI uri = exchange.getRequestURI();
      logger.info("Normal response: " + uri);
      Headers responseHeaders = exchange.getResponseHeaders();
      responseHeaders.add(HttpUtil.HTTP_HEADER_DATE, ServletBase.httpDateString());
      responseHeaders.add(HttpUtil.HTTP_HEADER_LOCATION, "/accessdenied");
      exchange.sendResponseHeaders(302, 0);
      exchange.getResponseBody().close();
    }
  }

  private final class AccessDeniedPageHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange)
        throws IOException {
      URI uri = exchange.getRequestURI();

      String responseString =
          "<http><head><title>A deny page </title><body>\n"
          + "<h1>Access Denied Page!</h1>\n"
          + "<p>denyphrase You have no access!</p>\n"
          + "</body></http>\n";
      logger.info("Access denied response: " + uri);
      Headers responseHeaders = exchange.getResponseHeaders();
      responseHeaders.add(HttpUtil.HTTP_HEADER_DATE, ServletBase.httpDateString());
      exchange.sendResponseHeaders(200, responseString.length());
      PrintWriter writer = new PrintWriter(exchange.getResponseBody());
      writer.write(responseString);
      writer.close();
      exchange.getResponseBody().close();
    }
  }
}
