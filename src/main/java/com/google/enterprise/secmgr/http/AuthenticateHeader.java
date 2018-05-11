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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.ListMultimap;
import com.google.enterprise.secmgr.common.HttpUtil;

import java.util.List;
import java.util.Objects;

import javax.annotation.concurrent.Immutable;

/**
 * A parser and data structure for HTTP WWW-Authenticate and Proxy-Authenticate
 * headers.  Used by {@link HttpAuthenticator} classes to decode HTTP
 * authentication headers.  See RFC 2617 for details.
 */
@Immutable
public final class AuthenticateHeader {
  public static final String PARAM_NAME_REALM = "realm";

  private final String authScheme;
  private final String realm;
  private final ImmutableListMultimap<String, String> parameters;

  private AuthenticateHeader(String authScheme) {
    this.authScheme = authScheme;
    this.realm = null;
    parameters = ImmutableListMultimap.<String, String>builder().build();
  }

  private AuthenticateHeader(String authScheme, String firstRealm,
      ImmutableListMultimap<String, String> parameters) {
    this.authScheme = authScheme;
    this.realm = firstRealm;
    this.parameters = parameters;
  }

  @VisibleForTesting
  static AuthenticateHeader makeForTest(String authScheme, String realm,
      ImmutableListMultimap<String, String> p) {
    return new AuthenticateHeader(authScheme, realm, p);
  }

  /**
   * Parse the value of a WWW-Authenticate header and return the parsed result.
   * The value is always of the form
   *     SCHEME (e.g. Negotiate, NTLM) or
   *     SCHEME NAME1=VALUE1,NAME2=VALUE2, ...
   *
   * If there are some name value pairs then one of them has to be "realm"
   * (case insensitive).
   *
   * @param headerValue The right-hand side of the header.
   * @return A parsed header.
   * @throws IllegalArgumentException if the argument can't be parsed.
   */
  public static AuthenticateHeader parse(String headerValue) {
    int space = headerValue.indexOf(' ');
    if (space < 0) {
      return new AuthenticateHeader(headerValue);
    }
    ImmutableListMultimap.Builder<String, String> builder = ImmutableListMultimap.builder();
    String authScheme = headerValue.substring(0, space);
    Preconditions.checkArgument(HttpUtil.isHttpToken(authScheme),
        "Authentication scheme must be an HTTP token: %s", authScheme);
    Iterable<String> authParams = Splitter.on(',').trimResults()
        .split(headerValue.substring(space + 1, headerValue.length()));
    int nRealms = 0;
    String firstRealm = null;
    for (String authParam : authParams) {
      List<String> nameValue = HttpUtil.parseHttpParameter(authParam);
      String key = nameValue.get(0);
      String value = nameValue.get(1);
      builder.put(key, value);
      if (PARAM_NAME_REALM.equalsIgnoreCase(key)) {
        nRealms++;
        if (null == firstRealm) {
          firstRealm = value;
        }
      }
    }
    Preconditions.checkArgument(nRealms >= 1,
        "No authentication realm found in header: %s", headerValue);
    ImmutableListMultimap<String, String> parameters = builder.build();
    return new AuthenticateHeader(authScheme, firstRealm, parameters);
  }

  /**
   * @return The authentication scheme for this header.
   */
  public String getAuthScheme() {
    return authScheme;
  }

  /**
   * Does this header have a given authentication scheme?
   *
   * @param theAuthScheme The authentication scheme to test for.
   * @return True if this header has the given authentication scheme.
   */
  public boolean hasAuthScheme(String theAuthScheme) {
    return authScheme.equalsIgnoreCase(theAuthScheme);
  }

  /**
   * @return The authentication realm for this header.  RFC 2617 doesn't forbid
   *     more than one realm; in that case the value is the first realm found.
   */
  public String getRealm() {
    return realm;
  }

  /**
   * @return The authentication parameters for this header, as an immutable
   *     multimap.  The parameter names are always in lower case.
   */
  public ListMultimap<String, String> getParameters() {
    return parameters;
  }

  /**
   * Test whether a given authentication scheme occurs in a list of headers.
   *
   * @param authScheme The authentication scheme to test for.
   * @param headers The list of headers to test.
   * @return True only if the authentication scheme occurs in the given headers.
   */
  public static boolean hasAuthScheme(String authScheme, List<AuthenticateHeader> headers) {
    for (AuthenticateHeader header : headers) {
      if (header.hasAuthScheme(authScheme)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append(authScheme);
    String prefix = " ";
    for (String name : parameters.keySet()) {
      for (String value : parameters.get(name)) {
        builder.append(prefix);
        prefix = ",";
        builder.append(name);
        builder.append("=");
        builder.append(HttpUtil.makeHttpParameterValueString(value));
      }
    }
    return builder.toString();
  }

  @Override
  public boolean equals(Object object) {
    if (!(object instanceof AuthenticateHeader)) { return false; }
    AuthenticateHeader other = (AuthenticateHeader) object;
    return Objects.equals(getAuthScheme(), other.getAuthScheme())
        && Objects.equals(getParameters(), other.getParameters());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getAuthScheme(), getParameters());
  }
}
