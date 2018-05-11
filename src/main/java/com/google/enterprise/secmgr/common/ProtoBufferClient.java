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
package com.google.enterprise.secmgr.common;

import com.google.protobuf.Message;

import java.io.IOException;
import java.net.URI;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;

/**
 * A client that sends a protocol-buffer request and receives a protocol-buffer
 * response.
 *
 * @param <Q> The message type used for requests.
 * @param <R> The message type used for responses.
 */
@ParametersAreNonnullByDefault
public interface ProtoBufferClient<Q extends Message, R extends Message> {
  /**
   * Performs a message exchange: sends a given request message to a service
   * specified with a given URI, then receives a response from the service and
   * returns it.
   *
   * @param request A request message to send.
   * @param uri A URI identifying the service to send the message to.
   * @return A response message as received from the service.
   * @throws IOException if there are any I/O errors during the exchange.
   */
  @Nonnull
  public R exchange(Q request, URI uri)
      throws IOException;
}
