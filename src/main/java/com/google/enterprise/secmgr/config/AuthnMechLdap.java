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

/**
 * LDAP configuration.
 */
public final class AuthnMechLdap extends AuthnMechanism {

  public static final String TYPE_NAME = "LDAP";
  private static final long DEFAULT_TRUST_DURATION = 20 * 60 * 1000;  // 20 mins

  private final boolean enableAuthn;
  private final boolean enableGroupLookup;
  private final boolean enableImplicitEveryone;

  private final String hostport;
  private final String bindDn;
  private final String password;
  private final String searchBase;
  private final String userSearchFilter;
  private final String groupSearchFilter;
  private final String groupFormat;
  private final int sslSupport;
  private final int supportedAuthMethods;

  private final int timeout;
  private final long trustDuration;

  /**
   * Make a new LDAP AuthN mechanism.
   *
   * @param hostport a hostname and port of the format "HOST:PORT"
   * @param bindDn the DN to bind with, or empty for anonymous binding
   * @param password the password to bind with, or empty for anonymous binding
   * @param searchBase component of DN common to all users
   * @param userSearchFilter filter used to search for user
   * @param groupSearchFilter filter used to find user's groups
   * @param groupFormat return format for the user's groups
   * @param sslSupport the type of SSL to use
   * @param supportedAuthMethods the auth methods supported by the server
   * @param enableAuthn whether this mech is enabled for authentication
   * @param enableGroupLookup whether this mech is enabled for doing groups lookup
   * @param timeout The request timeout in milliseconds.
   * @param trustDuration The number of milliseconds for which successfully
   *     verified credentials are trusted.  This must be a non-negative number.
   * @return A new mechanism with the given configuration
   */
  public static AuthnMechLdap make(String name, String hostport, String bindDn,
                                   String password, String searchBase,
                                   String userSearchFilter, String groupSearchFilter,
                                   String groupFormat,
                                   int sslSupport, int supportedAuthMethods,
                                   boolean enableAuthn, boolean enableGroupLookup,
                                   boolean enableImplicitEveryone, int timeout,
                                   long trustDuration) {
    return new AuthnMechLdap(name, hostport, bindDn, password, searchBase,
                             userSearchFilter, groupSearchFilter, groupFormat, sslSupport,
                             supportedAuthMethods, enableAuthn, enableGroupLookup,
                             enableImplicitEveryone, timeout, trustDuration);
  }

  private AuthnMechLdap(String name, String hostport, String bindDn, String password,
                        String searchBase, String userSearchFilter, String groupSearchFilter,
                        String groupFormat, int sslSupport, int supportedAuthMethods,
                        boolean enableAuthn, boolean enableGroupLookup,
                        boolean enableImplicitEveryone, int timeout, long trustDuration) {
    super(name);
    this.hostport = hostport;
    this.bindDn = bindDn;
    this.password = password;
    this.searchBase = searchBase;
    this.userSearchFilter = userSearchFilter;
    this.groupSearchFilter = groupSearchFilter;
    this.groupFormat = groupFormat;
    this.sslSupport = sslSupport;
    this.supportedAuthMethods = supportedAuthMethods;
    this.enableAuthn = enableAuthn;
    this.enableGroupLookup = enableGroupLookup;
    this.enableImplicitEveryone = enableImplicitEveryone;
    this.timeout = timeout;
    this.trustDuration = trustDuration;
  }

  public static AuthnMechLdap makeEmpty() {
    return new AuthnMechLdap();
  }

  private AuthnMechLdap() {
    super();
    this.hostport = null;
    this.bindDn = null;
    this.password = null;
    this.searchBase = null;
    this.userSearchFilter = null;
    this.groupSearchFilter = null;
    this.groupFormat = null;
    this.sslSupport = 0;
    this.supportedAuthMethods = 0;
    this.enableAuthn = false;
    this.enableGroupLookup = false;
    this.enableImplicitEveryone = false;
    this.timeout = NO_TIME_LIMIT;
    this.trustDuration = getDefaultTrustDuration();
  }

  public String getHostport() {
    return hostport;
  }

  public String getBindDn() {
    return bindDn;
  }

  public String getPassword() {
    return password;
  }

  public String getSearchBase() {
    return searchBase;
  }

  public String getUserSearchFilter() {
    return userSearchFilter;
  }

  public String getGroupSearchFilter() {
    return groupSearchFilter;
  }

  public String getGroupFormat() {
    return groupFormat;
  }

  public int getSslSupport() {
    return sslSupport;
  }

  public int getSupportedAuthMethods() {
    return supportedAuthMethods;
  }

  public boolean isEnableAuthn() {
    return enableAuthn;
  }

  public boolean isEnableGroupLookup() {
    return enableGroupLookup;
  }

  public boolean isEnableImplicitEveryone() {
    return enableImplicitEveryone;
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
    if (isEnableAuthn()) {
      builder.add(
          CredentialTransform.make(
              CredentialTypeSet.PRINCIPAL_AND_PASSWORD,
              CredentialTypeSet.VERIFIED_PRINCIPAL_AND_PASSWORD));
      builder.add(
          CredentialTransform.make(
              CredentialTypeSet.VERIFIED_PRINCIPAL,
              CredentialTypeSet.VERIFIED_PRINCIPAL));
    }
    if (isEnableGroupLookup()) {
      builder.add(
          CredentialTransform.make(
              CredentialTypeSet.VERIFIED_PRINCIPAL,
              CredentialTypeSet.VERIFIED_GROUPS));
    }
    return builder.build();
  }

  @Override
  public AuthnMechanism copyWithNewName(String name) {
    return make(name, getHostport(), getBindDn(), getPassword(), getSearchBase(),
        getUserSearchFilter(), getGroupSearchFilter(), getGroupFormat(), getSslSupport(),
        getSupportedAuthMethods(), isEnableAuthn(), isEnableGroupLookup(),
        isEnableImplicitEveryone(), getTimeout(), getTrustDuration());
  }

  public static long getDefaultTrustDuration() {
    return DEFAULT_TRUST_DURATION;
  }

  @Override
  public boolean equals(Object object) {
    if (object == this) { return true; }
    if (!(object instanceof AuthnMechLdap)) { return false; }
    AuthnMechLdap mech = (AuthnMechLdap) object;
    return super.equals(mech)
        && Objects.equals(getHostport(), mech.getHostport())
        && Objects.equals(getBindDn(), mech.getBindDn())
        && Objects.equals(getPassword(), mech.getPassword())
        && Objects.equals(getSearchBase(), mech.getSearchBase())
        && Objects.equals(getUserSearchFilter(), mech.getUserSearchFilter())
        && Objects.equals(getGroupSearchFilter(), mech.getGroupSearchFilter())
        && Objects.equals(getGroupFormat(), mech.getGroupFormat())
        && Objects.equals(getSslSupport(), mech.getSslSupport())
        && Objects.equals(getSupportedAuthMethods(), mech.getSupportedAuthMethods())
        && Objects.equals(isEnableAuthn(), mech.isEnableAuthn())
        && Objects.equals(isEnableGroupLookup(),  mech.isEnableGroupLookup())
        && Objects.equals(isEnableImplicitEveryone(), mech.isEnableImplicitEveryone())
        && Objects.equals(getTimeout(), mech.getTimeout())
        && Objects.equals(getTrustDuration(), mech.getTrustDuration());
  }

  @Override
  public int hashCode() {
    return super.hashCode(getHostport(), getBindDn(), getPassword(), getSearchBase(),
        getUserSearchFilter(), getGroupSearchFilter(), getGroupFormat(), getSslSupport(),
        getSupportedAuthMethods(), isEnableAuthn(), isEnableGroupLookup(),
        isEnableImplicitEveryone(), getTimeout(), getTrustDuration());
  }

  static void registerTypeAdapters(GsonBuilder builder) {
    builder.registerTypeAdapter(AuthnMechLdap.class,
        ProxyTypeAdapter.make(AuthnMechLdap.class, LocalProxy.class));
  }

  private static final class LocalProxy extends MechanismProxy<AuthnMechLdap> {
    boolean enableAuthn;
    boolean enableGroupLookup;
    boolean enableImplicitEveryone;
    String hostport;
    String bindDn;
    String password;
    String searchBase;
    String userSearchFilter;
    String groupSearchFilter;
    String groupFormat;
    int sslSupport;
    int supportedAuthMethods;
    int timeout = NO_TIME_LIMIT;
    long trustDuration = DEFAULT_TRUST_DURATION;

    @SuppressWarnings("unused")
    LocalProxy() {
    }

    @SuppressWarnings("unused")
    LocalProxy(AuthnMechLdap mechanism) {
      super(mechanism);
      hostport = mechanism.getHostport();
      bindDn = mechanism.getBindDn();
      password = mechanism.getPassword();
      searchBase = mechanism.getSearchBase();
      userSearchFilter = mechanism.getUserSearchFilter();
      groupSearchFilter = mechanism.getGroupSearchFilter();
      groupFormat = mechanism.getGroupFormat();
      sslSupport = mechanism.getSslSupport();
      supportedAuthMethods = mechanism.getSupportedAuthMethods();
      enableAuthn = mechanism.isEnableAuthn();
      enableGroupLookup = mechanism.isEnableGroupLookup();
      enableImplicitEveryone = mechanism.isEnableImplicitEveryone();
      timeout = mechanism.getTimeout();
      trustDuration = mechanism.getTrustDuration();
    }

    @Override
    public AuthnMechLdap build() {
      return make(name, hostport, bindDn, password, searchBase, userSearchFilter, groupSearchFilter,
          groupFormat, sslSupport, supportedAuthMethods, enableAuthn, enableGroupLookup,
          enableImplicitEveryone, timeout, trustDuration);
    }
  }
}
