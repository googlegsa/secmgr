// Copyright 2009 Google Inc.
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

package com.google.enterprise.secmgr.config;

import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.json.ProxyTypeAdapter;
import com.google.gson.GsonBuilder;

import java.util.List;
import java.util.Objects;

import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletRequest;

/**
 * The configuration of a sample-URL check authentication mechanism.
 */
@Immutable
public final class AuthnMechSampleUrl extends AuthnMechanism {

  public static final String TYPE_NAME = "SampleUrlCheck";
  public static final String DEFAULT_RETURN_URL_PARAMETER = "returnPath";
  private static final long DEFAULT_TRUST_DURATION = 5 * 60 * 1000;  // five minutes

  private final String sampleUrl;
  private final String redirectUrl;
  private final String returnUrlParameter;
  private final int timeout;
  private final long trustDuration;

  /**
   * Make a new sample-URL cookie mechanism.
   *
   * @param sampleUrl A sample URL that requires cookie authentication.
   * @param redirectUrl A URL to redirect the user agent to in order to get the cookie(s).
   * @param timeout The timeout in milliseconds.
   * @param trustDuration The number of milliseconds that successfully
   *     verified credentials are trusted.  This must be a non-negative number.
   * @return A new mechanism with the given elements.
   */
  public static AuthnMechSampleUrl make(String name, String sampleUrl, String redirectUrl,
      String returnUrlParameter, int timeout, long trustDuration) {
    return new AuthnMechSampleUrl(name, sampleUrl, redirectUrl, returnUrlParameter, timeout,
                                  trustDuration);
  }

  /**
   * Make a new sample-URL cookie mechanism with a default timeout and trust duration.
   *
   * @param sampleUrl A sample URL that requires cookie authentication.
   * @param redirectUrl A URL to redirect the user agent to in order to get the cookie(s).
   * @return A new mechanism with the given elements.
   */
  public static AuthnMechSampleUrl make(String name, String sampleUrl, String redirectUrl) {
    return make(name, sampleUrl, redirectUrl, getDefaultReturnUrlParameter(),
        NO_TIME_LIMIT, getDefaultTrustDuration());
  }

  private AuthnMechSampleUrl(String name, String sampleUrl, String redirectUrl,
      String returnUrlParameter, int timeout, long trustDuration) {
    super(name);
    this.sampleUrl = checkStringOrNull(sampleUrl);
    this.redirectUrl = checkStringOrNull(redirectUrl);
    this.returnUrlParameter = checkStringOrNull(returnUrlParameter);
    this.timeout = checkTimeout(timeout);
    this.trustDuration = checkTrustDuration(trustDuration);
  }

  /**
   * Make a new unconfigured sample-URL cookie mechanism.
   */
  public static AuthnMechSampleUrl makeEmpty() {
    return new AuthnMechSampleUrl();
  }

  private AuthnMechSampleUrl() {
    super();
    this.sampleUrl = null;
    this.redirectUrl = null;
    this.returnUrlParameter = getDefaultReturnUrlParameter();
    this.timeout = NO_TIME_LIMIT;
    this.trustDuration = getDefaultTrustDuration();
  }

  @Override
  public String getTypeName() {
    return TYPE_NAME;
  }

  public static String getDefaultReturnUrlParameter() {
    return DEFAULT_RETURN_URL_PARAMETER;
  }

  /**
   * Get the default trust-duration value.
   */
  public static long getDefaultTrustDuration() {
    return DEFAULT_TRUST_DURATION;
  }

  @Override
  public boolean isApplicable(HttpServletRequest request) {
    // May check if there are cookie. But the rest of the logic should take care of it if the cookie
    // is not present.
    return (request != null);
  }

  @Override
  public List<CredentialTransform> getCredentialTransforms() {
    if (redirectUrl != null) {
      return ImmutableList.of();
    }
    return ImmutableList.of(
        CredentialTransform.make(CredentialTypeSet.COOKIES, CredentialTypeSet.VERIFIED_PRINCIPAL),
        CredentialTransform.make(CredentialTypeSet.COOKIES, CredentialTypeSet.VERIFIED_ALIASES),
        CredentialTransform.make(CredentialTypeSet.COOKIES, CredentialTypeSet.VERIFIED_GROUPS));
  }

  @Override
  public AuthnMechanism copyWithNewName(String name) {
    return make(name, getSampleUrl(), getRedirectUrl(), getReturnUrlParameter(),
        getTimeout(), getTrustDuration());
  }

  @Override
  public String getSampleUrl() {
    return sampleUrl;
  }

  /**
   * Gets the redirect URL associated with this authority.
   *
   * @return The redirect URL as a string, or {@code null} if none exists.
   */
  public String getRedirectUrl() {
    return redirectUrl;
  }

  /**
   * Gets the return-URL parameter associated with this authority.
   *
   * This is the name of the request/CGI param we set on an outbound redirect,
   * which tells the server on the receiving end of the redirect where to
   * redirect back to once it's done.
   *
   * The default value for this is {@code "returnPath"}.
   *
   * @return The return url parameter string, or {@code null} for default.
   */
  public String getReturnUrlParameter() {
    return returnUrlParameter;
  }

  @Override
  public int getTimeout() {
    return timeout;
  }

  @Override
  public long getTrustDuration() {
    return trustDuration;
  }

  @Override
  public boolean equals(Object object) {
    if (object == this) { return true; }
    if (!(object instanceof AuthnMechSampleUrl)) { return false; }
    AuthnMechSampleUrl mech = (AuthnMechSampleUrl) object;
    return super.equals(mech)
        && Objects.equals(getSampleUrl(), mech.getSampleUrl())
        && Objects.equals(getRedirectUrl(), mech.getRedirectUrl())
        && Objects.equals(getReturnUrlParameter(), mech.getReturnUrlParameter())
        && Objects.equals(getTimeout(), mech.getTimeout())
        && Objects.equals(getTrustDuration(), mech.getTrustDuration());
  }

  @Override
  public int hashCode() {
    return super.hashCode(getSampleUrl(), getRedirectUrl(), getReturnUrlParameter(),
        getTimeout(), getTrustDuration());
  }

  static void registerTypeAdapters(GsonBuilder builder) {
    builder.registerTypeAdapter(AuthnMechSampleUrl.class,
        ProxyTypeAdapter.make(AuthnMechSampleUrl.class, LocalProxy.class));
  }

  private static final class LocalProxy extends MechanismProxy<AuthnMechSampleUrl> {
    String sampleUrl;
    String redirectUrl;
    String returnUrlParameter = DEFAULT_RETURN_URL_PARAMETER;
    int timeout = NO_TIME_LIMIT;
    long trustDuration = DEFAULT_TRUST_DURATION;

    @SuppressWarnings("unused")
    LocalProxy() {
    }

    @SuppressWarnings("unused")
    LocalProxy(AuthnMechSampleUrl mechanism) {
      super(mechanism);
      sampleUrl = mechanism.getSampleUrl();
      redirectUrl = mechanism.getRedirectUrl();
      returnUrlParameter = mechanism.getReturnUrlParameter();
      timeout = mechanism.getTimeout();
      trustDuration = mechanism.getTrustDuration();
    }

    @Override
    public AuthnMechSampleUrl build() {
      return make(name, sampleUrl, redirectUrl, returnUrlParameter, timeout, trustDuration);
    }
  }
}
