// Copyright 2013 Google Inc.
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
 * The configuration of a pre-authenticated mechanism.
 * We assume the user has been authenticated externally and just mark it verified here.
 */
@Immutable
public final class AuthnMechPreauthenticated extends AuthnMechanism {

  public static final String TYPE_NAME = "Preauthenticated";
  private static final long DEFAULT_TRUST_DURATION = 20 * 60 * 1000;  // 20 mins

  private final int timeout;
  private final long trustDuration;

  /**
   * Make a new preauthenticated mechanism.
   *
   * @param name The name of the mechanism.
   * @param trustDuration The number of milliseconds for which successfully
   *     verified credentials are trusted.  This must be a non-negative number.
   * @return A new mechanism with the given elements.
   */
  public static AuthnMechPreauthenticated make(String name, int timeout,
                                    long trustDuration) {
    return new AuthnMechPreauthenticated(name, timeout, trustDuration);
  }

  /**
   * Make a new preauthenticated mechanism with a default timeout and trust duration.
   *
   * @param name The name of the mechanism.
   * @return A new mechanism with the given elements.
   */
  public static AuthnMechPreauthenticated make(String name) {
    return make(name, NO_TIME_LIMIT, getDefaultTrustDuration());
  }

  private AuthnMechPreauthenticated(String name, int timeout, long trustDuration) {
    super(name);
    this.timeout = checkTimeout(timeout);
    this.trustDuration = checkTrustDuration(trustDuration);
  }

  /**
   * Make a new unconfigured preauthenticated mechanism.
   */
  public static AuthnMechPreauthenticated makeEmpty() {
    return new AuthnMechPreauthenticated();
  }

  private AuthnMechPreauthenticated() {
    super();
    this.timeout = NO_TIME_LIMIT;
    this.trustDuration = getDefaultTrustDuration();
  }

  @Override
  public String getTypeName() {
    return TYPE_NAME;
  }

  /**
   * Get the default trust-duration value.
   */
  public static long getDefaultTrustDuration() {
    return DEFAULT_TRUST_DURATION;
  }

  @Override
  public List<CredentialTransform> getCredentialTransforms() {
    return ImmutableList.of(
        CredentialTransform.make(
            CredentialTypeSet.PRINCIPAL_AND_PASSWORD,
            CredentialTypeSet.VERIFIED_PRINCIPAL_AND_PASSWORD));
  }

  @Override
  public boolean isApplicable(HttpServletRequest request) {
    return (request == null);
  }

  @Override
  public AuthnMechanism copyWithNewName(String name) {
    return make(name, getTimeout(), getTrustDuration());
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
    if (!(object instanceof AuthnMechPreauthenticated)) { return false; }
    AuthnMechPreauthenticated mech = (AuthnMechPreauthenticated) object;
    return super.equals(mech)
        && Objects.equals(getTimeout(), mech.getTimeout())
        && Objects.equals(getTrustDuration(), mech.getTrustDuration());
  }

  @Override
  public int hashCode() {
    return super.hashCode(getTimeout(), getTrustDuration());
  }

  static void registerTypeAdapters(GsonBuilder builder) {
    builder.registerTypeAdapter(AuthnMechPreauthenticated.class,
        ProxyTypeAdapter.make(AuthnMechPreauthenticated.class, LocalProxy.class));
  }

  private static final class LocalProxy extends MechanismProxy<AuthnMechPreauthenticated> {
    int timeout = NO_TIME_LIMIT;
    long trustDuration = DEFAULT_TRUST_DURATION;

    @SuppressWarnings("unused")
    LocalProxy() {
    }

    @SuppressWarnings("unused")
    LocalProxy(AuthnMechPreauthenticated mechanism) {
      super(mechanism);
      timeout = mechanism.getTimeout();
      trustDuration = mechanism.getTrustDuration();
    }

    @Override
    public AuthnMechPreauthenticated build() {
      return make(name, timeout, trustDuration);
    }
  }
}
