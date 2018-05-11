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

import org.apache.http.protocol.BasicHttpContext;

import javax.annotation.Nonnull;

/**
 * HttpExchangeContext implementation that contains a BasicHttpContext.
 *
 */
public class BasicHttpExchangeContext implements HttpExchangeContext {

  @Nonnull private final BasicHttpContext context;

  public BasicHttpExchangeContext() {
    this.context = new BasicHttpContext();
  }

  @Nonnull
  public BasicHttpContext getContext() {
    return this.context;
  }
}
