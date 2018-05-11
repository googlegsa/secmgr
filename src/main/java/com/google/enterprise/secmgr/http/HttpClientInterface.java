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

package com.google.enterprise.secmgr.http;

import com.google.common.collect.ListMultimap;

import java.net.URL;

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

/**
 * An abstraction to hide HttpClient behind.
 * This allows HTTP transport to be mocked for testing.
 */
@ParametersAreNonnullByDefault
public interface HttpClientInterface {
  /**
   * Creates a new HTTP HEAD exchange object.
   *
   * @param url A URL to send the request to.
   * @return A new HTTP exchange object.
   */
  @Nonnull
  public HttpExchange headExchange(URL url);

  /**
   * Creates a new HTTP GET exchange object.
   *
   * @param url A URL to send the request to.
   * @return A new HTTP exchange object.
   */
  @Nonnull
  public HttpExchange getExchange(URL url);

  /**
   * Creates a new HTTP GET exchange object with a given byte-length limit.
   * This is a convenience method.
   *
   * @param url A URL to send the request to.
   * @param length A byte-length limit for the response.
   * @return A new HTTP exchange object.
   */
  @Nonnull
  public HttpExchange getExchange(URL url, @Nonnegative int length);

  /**
   * Create a new HTTP GET exchange object with the given exchange context.
   * This allows the reuse of a context/connection from a previous exchange.
   *
   * @param url A URL to send the request to.
   * @param context A HttpExchangeContext object.
   * @return A new HTTP exchange object.
   */
  @Nonnull
  public HttpExchange getExchange(URL url, HttpExchangeContext context);

  /**
   * Creates a new HTTP POST exchange object.
   *
   * @param url A URL to send the request to.
   * @param parameters Some POST parameters, or {@code null} if the caller will
   *     fill in the body.
   * @return A new HTTP exchange object.
   */
  @Nonnull
  public HttpExchange postExchange(URL url, @Nullable ListMultimap<String, String> parameters);

  /**
   * Creates a new HTTP GET or HEAD exchange object.  The method (GET or HEAD)
   * is determined by the deny-rules configured for the given URL.
   *
   * @param url A URL to send the request to.
   * @return A new HTTP exchange object.
   */
  @Nonnull
  public HttpExchange newHttpExchange(URL url);

  /**
   * Gets a new disposable, single connection HTTP client.
   * Used to guarantee that a sequence of messages all use the same connection.
   */
  @Nonnull
  public HttpClientInterface newSingleUseInstance();
}
