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

import static com.google.enterprise.secmgr.common.SecurityManagerUtil.bytesToHex;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.enterprise.secmgr.common.Base64;
import com.google.enterprise.secmgr.common.Base64DecoderException;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.ntlmssp.NtlmAuthenticate;
import com.google.enterprise.secmgr.ntlmssp.NtlmChallenge;
import com.google.enterprise.secmgr.ntlmssp.NtlmV1Client;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Objects;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletResponse;

/**
 * An authenticator that handles NTLM authentication over HTTP client.
 */
@Immutable
public final class NtlmHttpAuthenticator implements HttpAuthenticator {
  private static final Logger logger = Logger.getLogger(NtlmHttpAuthenticator.class.getName());
  private static final String AUTH_SCHEME = "NTLM";
  private static final int PREFERENCE_RANK = 2;

  private final String domain;
  private final String userName;
  private final String password;

  private NtlmHttpAuthenticator(String domain, String userName, String password) {
    this.domain = domain;
    this.userName = userName;
    this.password = password;
  }

  public static HttpAuthenticator make(String domain, String userName, String password) {
    Preconditions.checkArgument(!Strings.isNullOrEmpty(userName));
    Preconditions.checkArgument(!Strings.isNullOrEmpty(password));
    return new NtlmHttpAuthenticator(domain, userName, password);
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
    Decorator decorator = requester.getLogDecorator();

    // Do the NTLM hand shakes and return the final result.
    // The previous response indicated NTLM by the time it reaches here.
    int status1 = previousResult.getStatusCode();

    boolean forProxy;
    if (status1 == HttpServletResponse.SC_UNAUTHORIZED) {
      forProxy = false;
    } else if (status1 == HttpServletResponse.SC_PROXY_AUTHENTICATION_REQUIRED) {
      forProxy = true;
    } else {
      throw new HttpAuthenticatorException("Expecting to get 401, but got " + status1);
    }

    NtlmV1Client client = NtlmV1Client.builder()
        .setDomainName(domain)
        .setUserName(userName)
        .setPassword(password)
        .setWorkstationName(null)
        .build();

    byte[] encodedNegotiate = client.createNegotiateMessage().encode();
    logger.info(
        decorator.apply("Sending NTLM Negotiate: " + bytesToHex(encodedNegotiate)));

    // in order to persist the connection between exchanges in the course of
    // the NTLM auth, we create a localContext that gets shared by all of the
    // exchanges for this auth
    HttpClientInterface httpClient = HttpClientUtil.newSingleUseClient();
    HttpExchangeContext localContext = new BasicHttpExchangeContext();
    HttpExchange exchange = getExchange(httpClient, url, localContext);
    try {

      setNtlmHeader(exchange, forProxy, encodedNegotiate);
      PageFetcherResult result2 =
          requester.runExchange(exchange, getBody, previousResult);
      int status2 = result2.getStatusCode();
      if (status2 != status1) {
        throw new HttpAuthenticatorException(
            "Expecting to get " + status1 + " from server, but got " + status2);
      }

      byte[] encodedChallenge = findNtlmHeader(exchange, forProxy, true);
      logger.info(
          decorator.apply("Received NTLM Challenge: " + bytesToHex(encodedChallenge)));

      NtlmChallenge challenge;
      try {
        challenge = NtlmChallenge.decode(encodedChallenge);
      } catch (UnsupportedEncodingException e) {
        throw new HttpAuthenticatorException(e);
      }
      logger.info(
          decorator.apply("NTLM challenge: " + bytesToHex(challenge.getServerChallenge())));

      try {
        client.setChallengeMessage(challenge);
      } catch (IllegalArgumentException e) {
        throw new HttpAuthenticatorException(e);
      }

      NtlmAuthenticate authenticate;
      try {
        authenticate = client.createAuthenticateMessage();
      } catch (GeneralSecurityException e) {
        throw new HttpAuthenticatorException(e);
      }
      logger.info(decorator.apply(
          "LM response: " + bytesToHex(authenticate.getLmChallengeResponse())));
      logger.info(decorator.apply(
          "NTLM response: " + bytesToHex(authenticate.getNtChallengeResponse())));

      byte[] encodedAuthenticate;
      try {
        encodedAuthenticate = authenticate.encode();
      } catch (UnsupportedEncodingException e) {
        throw new HttpAuthenticatorException(e);
      }
      logger.info(
          decorator.apply("Sending NTLM Authenticate: " + bytesToHex(encodedAuthenticate)));

      exchange = getExchange(httpClient, url, localContext);
      setNtlmHeader(exchange, forProxy, encodedAuthenticate);
      PageFetcherResult result3 =
          requester.runExchange(exchange, getBody, previousResult);

      return result3;

    } finally {
      exchange.close();
    }
  }

  public String getUserName() {
    return userName;
  }

  public String getPassword() {
    return password;
  }

  @Override
  public boolean equals(Object object) {
    if (!(object instanceof NtlmHttpAuthenticator)) {
      return false;
    }
    NtlmHttpAuthenticator other = (NtlmHttpAuthenticator) object;
    return Objects.equals(getUserName(), other.getUserName())
        && Objects.equals(getPassword(), other.getPassword());
  }

  @Override
  public int hashCode() {
    return Objects.hash(AUTH_SCHEME, getUserName(), getPassword());
  }

  // We have to use a new Exchange object for each pair of request/response
  // as there is no removeHttpHeader() method.
  private HttpExchange getExchange(HttpClientInterface httpClient, URL sampleUrl, 
      HttpExchangeContext context) {
    HttpExchange exchange = HttpClientUtil.getExchange(httpClient, sampleUrl, context);
    exchange.setRequestHeader(HttpUtil.HTTP_HEADER_CONNECTION, HttpUtil.KEEP_ALIVE);
    exchange.setRequestHeader(HttpUtil.HTTP_HEADER_USER_AGENT, HttpUtil.USER_AGENT);
    return exchange;
  }

  private static byte[] findNtlmHeader(HttpExchange exchange, boolean forProxy, boolean hasMessage)
      throws HttpAuthenticatorException {
    List<String> values
        = exchange.getResponseHeaderValues(forProxy
            ? HttpUtil.HTTP_HEADER_PROXY_AUTHENTICATE
            : HttpUtil.HTTP_HEADER_WWW_AUTHENTICATE);
    if (values != null) {
      for (String value : values) {
        String[] parts = value.split(" +");
        if (parts.length == (hasMessage ? 2 : 1)
            && AUTH_SCHEME.equalsIgnoreCase(parts[0])) {
          if (!hasMessage) {
            return null;
          }
          try {
            return Base64.decode(parts[1]);
          } catch (Base64DecoderException e) {
            throw new HttpAuthenticatorException(
                "Could not decode server auth response: " + parts[1]);
          }
        }
      }
    }
    throw new HttpAuthenticatorException("Server not setting NTLM headers");
  }

  private static void setNtlmHeader(HttpExchange exchange, boolean forProxy, byte[] message) {
    exchange.setRequestHeader(forProxy
        ? HttpUtil.HTTP_HEADER_PROXY_AUTHORIZATION
        : HttpUtil.HTTP_HEADER_AUTHORIZATION,
        AUTH_SCHEME + " " + Base64.encode(message));
  }
}
