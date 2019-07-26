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
import com.google.common.base.Supplier;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.ProtoBufferClient;
import com.google.protobuf.Message;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletResponse;

/**
 * A proto-buffer-over-HTTP client.
 *
 * @param <Q> A message type for the request.
 * @param <R> A message type for the response.
 */
@Immutable
@ParametersAreNonnullByDefault
public final class HttpProtoBufferClient<Q extends Message, R extends Message>
    implements ProtoBufferClient<Q, R> {

  private final int timeout;
  private final Supplier<? extends Message.Builder> responseBuilderFactory;
  private final Class<R> responseType;
  private final String contentType;

  private HttpProtoBufferClient(
      int timeout,
      Supplier<? extends Message.Builder> responseBuilderFactory,
      Class<R> responseType,
      String contentType) {
    this.timeout = timeout;
    this.responseBuilderFactory = responseBuilderFactory;
    this.responseType = responseType;
    this.contentType = contentType;
  }

  @Nonnull
  public static <Q1 extends Message, R1 extends Message> ProtoBufferClient<Q1, R1> make(
      int timeout,
      Supplier<? extends Message.Builder> responseBuilderFactory,
      Class<R1> responseType,
      String contentType) {
    Preconditions.checkNotNull(responseBuilderFactory);
    Preconditions.checkNotNull(responseType);
    Preconditions.checkNotNull(contentType);
    return new HttpProtoBufferClient<>(
        timeout, responseBuilderFactory, responseType, contentType);
  }

  @Override
  public R exchange(Q request, URI uri)
      throws IOException {
    Preconditions.checkNotNull(request);
    Preconditions.checkNotNull(uri);
    URL convertedUrl;
    try {
      convertedUrl = uri.toURL();
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException(e);
    }
    HttpExchange httpExchange = HttpClientUtil.postExchange(convertedUrl, null);
    try {
      httpExchange.setTimeout(timeout);
      httpExchange.setRequestHeader(HttpUtil.HTTP_HEADER_CONTENT_TYPE, contentType);
      httpExchange.setRequestBody(request.toByteArray());

      int status = httpExchange.exchange();
      if (status != HttpServletResponse.SC_OK) {
        throw new IOException("Incorrect HTTP status: " + status);
      }

      Message.Builder builder = responseBuilderFactory.get();
      InputStream input = httpExchange.getResponseEntityAsStream();
      try {
        builder.mergeFrom(input);
      } finally {
        input.close();
      }
      return responseType.cast(builder.build());
    } finally {
      httpExchange.close();
    }
  }
}
