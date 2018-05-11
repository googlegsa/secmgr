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

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.enterprise.secmgr.common.Base64;
import com.google.enterprise.secmgr.common.HttpUtil;

import java.io.IOException;
import java.net.URL;
import java.util.Objects;

import javax.annotation.concurrent.Immutable;

/**
 * An authenticator that handles HTTP Basic authentication.
 */
@Immutable
public final class BasicHttpAuthenticator implements HttpAuthenticator {
  private static final String AUTH_SCHEME = "Basic";
  private static final int PREFERENCE_RANK = 1;

  private final String userName;
  private final String password;

  private BasicHttpAuthenticator(String userName, String password) {
    this.userName = userName;
    this.password = password;
  }

  public static HttpAuthenticator make(String userName, String password) {
    Preconditions.checkArgument(!Strings.isNullOrEmpty(userName));
    Preconditions.checkArgument(!Strings.isNullOrEmpty(password));
    return new BasicHttpAuthenticator(userName, password);
  }

  @Override
  public boolean isApplicable(PageFetcherResult previousResult) {
    return previousResult.needsHttpAuthentication(AUTH_SCHEME);
  }

  @Override
  public int getPreferenceRank() {
    return PREFERENCE_RANK;
  }

  @Override
  public PageFetcherResult apply(PageFetcherResult previousResult, HttpRequester requester, URL url,
      boolean getBody)
      throws IOException {
    URL authUrl;

    if (null == previousResult || null == previousResult.getRedirectUrl()) {
      authUrl = url;
    } else {
      authUrl = previousResult.getRedirectUrl();
    }

    HttpExchange exchange = null;
    if (getBody) {
      exchange = HttpClientUtil.getExchange(authUrl);
    } else {
      exchange = HttpClientUtil.newHttpExchange(authUrl);
    }
    exchange.setRequestHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION,
        AUTH_SCHEME + " " + Base64.encode((userName + ":" + password).getBytes("UTF-8")));
    PageFetcherResult result = requester.runExchangeRedirect(exchange, getBody, previousResult);
    if (200 <= result.getStatusCode() && 300 > result.getStatusCode()) {
      KnownAuthSchemers.getInstance().addKnown(authUrl, AUTH_SCHEME);
    }
    return result;
  }

  public String getUserName() {
    return userName;
  }

  public String getPassword() {
    return password;
  }

  @Override
  public boolean equals(Object object) {
    if (!(object instanceof BasicHttpAuthenticator)) {
      return false;
    }
    BasicHttpAuthenticator other = (BasicHttpAuthenticator) object;
    return Objects.equals(getUserName(), other.getUserName())
        && Objects.equals(getPassword(), other.getPassword());
  }

  @Override
  public int hashCode() {
    return Objects.hash(AUTH_SCHEME, getUserName(), getPassword());
  }
}
