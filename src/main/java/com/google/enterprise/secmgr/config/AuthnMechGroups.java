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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.json.ProxyTypeAdapter;
import com.google.gson.GsonBuilder;

import java.util.List;
import java.util.Objects;

/**
 * Groups configuration.
 */
public final class AuthnMechGroups extends AuthnMechanism {

  public static final String TYPE_NAME = "Groups";
  private static final long DEFAULT_TRUST_DURATION = 20 * 60 * 1000;  // 20 mins

  private final int timeout;
  private final long trustDuration;
  
  private static String groupsMechNameSuffix = null;

  /**
   * Make a new AuthnMechGroups mechanism.
   *
   * @param name The name for the mechanism.
   * @param timeout The request timeout in milliseconds.
   * @param trustDuration The number of milliseconds for which successfully
   *     verified credentials are trusted.  This must be a non-negative number.
   * @return A new mechanism with the given configuration
   */
  public static AuthnMechGroups make(String name, int timeout, long trustDuration) {
    return new AuthnMechGroups(name, timeout, trustDuration);
  }

  /**
   * Make a new AuthnMechGroups mechanism.
   *
   * @param name The name for the mechanism.
   * @return A new mechanism with the given configuration
   */
  public static AuthnMechGroups make(String name) {
    return new AuthnMechGroups(name, AuthnMechanism.NO_TIME_LIMIT, DEFAULT_TRUST_DURATION);
  }

  /**
   * Make a new AuthnMechGroups mechanism. If the groupsMechNameSuffix is not null,
   * we return the groups mechansim with credentialGroupName_groups_groupsMechNameSuffix.
   * Otherwise, we return the groups mechanism with credentialGroupName_groups_randomnumber.
   *
   * @param credentialGroupName The credential group name.
   * @return A new mechanism with the given configuration
   */
  public static AuthnMechGroups makeForCredentialGroup(String credentialGroupName) {
    return new AuthnMechGroups(
        (groupsMechNameSuffix == null) ?
        credentialGroupName + "_groups_" + SecurityManagerUtil.generateRandomNonceHex(16) :
        credentialGroupName + "_groups_" + groupsMechNameSuffix,
        AuthnMechanism.NO_TIME_LIMIT,
        DEFAULT_TRUST_DURATION);
  }

  @VisibleForTesting
  public static void setGroupsNameSuffix(String suffix) {
    groupsMechNameSuffix = suffix;
  }

  private AuthnMechGroups(String name, int timeout, long trustDuration) {
    super(name);
    this.timeout = timeout;
    this.trustDuration = trustDuration;
  }

  public static AuthnMechGroups makeEmpty() {
    return new AuthnMechGroups();
  }

  private AuthnMechGroups() {
    super();
    this.timeout = NO_TIME_LIMIT;
    this.trustDuration = getDefaultTrustDuration();
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
  public String getTypeName() {
    return TYPE_NAME;
  }

  @Override
  public List<CredentialTransform> getCredentialTransforms() {
    ImmutableList.Builder<CredentialTransform> builder = ImmutableList.builder();
    builder.add(
        CredentialTransform.make(
            CredentialTypeSet.VERIFIED_PRINCIPAL,
            CredentialTypeSet.VERIFIED_GROUPS));
    return builder.build();
  }

  @Override
  public AuthnMechanism copyWithNewName(String name) {
    return make(name, getTimeout(), getTrustDuration());
  }

  public static long getDefaultTrustDuration() {
    return DEFAULT_TRUST_DURATION;
  }

  @Override
  public boolean equals(Object object) {
    if (object == this) { return true; }
    if (!(object instanceof AuthnMechGroups)) { return false; }
    AuthnMechGroups mech = (AuthnMechGroups) object;
    return super.equals(mech)
        && Objects.equals(getTimeout(), mech.getTimeout())
        && Objects.equals(getTrustDuration(), mech.getTrustDuration());
  }

  @Override
  public int hashCode() {
    return super.hashCode(getTimeout(), getTrustDuration());
  }

  static void registerTypeAdapters(GsonBuilder builder) {
    builder.registerTypeAdapter(AuthnMechGroups.class,
        ProxyTypeAdapter.make(AuthnMechGroups.class, LocalProxy.class));
  }

  private static final class LocalProxy extends MechanismProxy<AuthnMechGroups> {
    int timeout = NO_TIME_LIMIT;
    long trustDuration = DEFAULT_TRUST_DURATION;

    @SuppressWarnings("unused")
    LocalProxy() {
    }

    @SuppressWarnings("unused")
    LocalProxy(AuthnMechGroups mechanism) {
      super(mechanism);
      timeout = mechanism.getTimeout();
      trustDuration = mechanism.getTrustDuration();
    }

    @Override
    public AuthnMechGroups build() {
      return make(name, timeout, trustDuration);
    }
  }
}
