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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.json.ProxyTypeAdapter;
import com.google.enterprise.secmgr.json.TypeAdapters;
import com.google.enterprise.secmgr.json.TypeProxy;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import javax.annotation.Nonnull;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;

/**
 * A class that holds a complete security manager configuration.
 */
@ThreadSafe
public final class SecurityManagerConfig {
  static final int CURRENT_VERSION = 8;

  private final int version;
  @GuardedBy("this") private ImmutableList<CredentialGroup> credentialGroups;
  @GuardedBy("this") private ImmutableList<AuthnMechanism> mechanisms;
  @GuardedBy("this") private ConfigParams params;
  @GuardedBy("this") private FlexAuthorizer flexAuthorizer;

  private SecurityManagerConfig(int version, ImmutableList<CredentialGroup> credentialGroups,
      ConfigParams params, FlexAuthorizer flexAuthorizer) {
    this.version = version;
    setCredentialGroupsInternal(credentialGroups);
    this.params = params;
    this.flexAuthorizer = flexAuthorizer;
  }

  /**
   * Set a configuration's credential groups.  The security manager uses this
   * only for testing.
   *
   * @param credentialGroups The new credential groups.
   * @throws IllegalArgumentException if there's a problem with the argument.
   */
  public void setCredentialGroupsInternal(ImmutableList<CredentialGroup> credentialGroups) {
    ImmutableList.Builder<AuthnMechanism> mechanismsBuilder = ImmutableList.builder();
    for (CredentialGroup credentialGroup : credentialGroups) {
      mechanismsBuilder.addAll(credentialGroup.getMechanisms());
    }
    ImmutableList<AuthnMechanism> mechanisms = mechanismsBuilder.build();
    synchronized (this) {
      this.credentialGroups = credentialGroups;
      this.mechanisms = mechanisms;
    }
  }

  /**
   * Make a security manager configuration.
   *
   * @param credentialGroups The configuration's credential groups.
   * @param params The configuration's parameters.
   * @param flexAuthorizer The flex authorization configs
   * @return A security manager configuration.
   */
  public static SecurityManagerConfig make(Iterable<CredentialGroup> credentialGroups,
      ConfigParams params, FlexAuthorizer flexAuthorizer) {
    Preconditions.checkArgument(params != null);
    Preconditions.checkArgument(flexAuthorizer != null);
    return new SecurityManagerConfig(CURRENT_VERSION, checkCredentialGroups(credentialGroups),
        params, flexAuthorizer);
  }

  @VisibleForTesting
  public static SecurityManagerConfig make(Iterable<CredentialGroup> credentialGroups) {
    return new SecurityManagerConfig(CURRENT_VERSION, checkCredentialGroups(credentialGroups),
        ConfigParams.makeDefault(),
        FlexAuthorizerImpl.makeDefault());
  }

  static SecurityManagerConfig makeInternal(int version, Iterable<CredentialGroup> credentialGroups,
      ConfigParams params, FlexAuthorizer flexAuthorizer) {
    Preconditions.checkArgument(version > 0 && version <= CURRENT_VERSION);
    return new SecurityManagerConfig(
        version,
        checkCredentialGroups(credentialGroups),
        (params != null) ? params : ConfigParams.makeDefault(),
        (flexAuthorizer != null) ? flexAuthorizer : FlexAuthorizerImpl.makeDefault());
  }

  private static ImmutableList<CredentialGroup> checkCredentialGroups(
      Iterable<CredentialGroup> credentialGroups) {
    Preconditions.checkNotNull(credentialGroups);
    ImmutableList<CredentialGroup> copy = ImmutableList.copyOf(credentialGroups);
    Collection<String> names = Lists.newArrayList();
    for (CredentialGroup group : copy) {
      checkConfigName(group.getName(), names);
      for (AuthnMechanism mech : group.getMechanisms()) {
        checkConfigName(mech.getName(), names);
      }
    }
    return copy;
  }

  private static void checkConfigName(String name, Collection<String> names) {
    if (name != null) {
      name = name.toLowerCase(Locale.US);
      Preconditions.checkArgument(!names.contains(name),
          "Configuration name appears more than once: %s", name);
      names.add(name);
    }
  }

  /**
   * @return A default security manager configuration.
   */
  public static SecurityManagerConfig makeDefault() {
    return SecurityManagerConfig.make(
        makeDefaultCredentialGroups(),
        ConfigParams.makeDefault(),
        FlexAuthorizerImpl.makeDefault());
  }

  public static ImmutableList<CredentialGroup> makeDefaultCredentialGroups() {
    return ImmutableList.of(CredentialGroup.builder()
        .addMechanism(AuthnMechGroups.makeForCredentialGroup("Default"))
        .build());
  }

  /**
   * @return The configuration's version.
   */
  int getVersion() {
    return version;
  }

  /**
   * Gets the credential groups contained in this configuration.
   *
   * @return The credential groups as an immutable list.  The order is the same
   *     as was given when this configuration was created.
   */
  public synchronized ImmutableList<CredentialGroup> getCredentialGroups() {
    return credentialGroups;
  }

  /**
   * Set a configuration's credential groups.  The security manager uses this
   * only for testing.
   *
   * @param credentialGroups The new credential groups.
   * @throws IllegalArgumentException if there's a problem with the argument.
   */
  public void setCredentialGroups(Iterable<CredentialGroup> credentialGroups) {
    setCredentialGroupsInternal(checkCredentialGroups(credentialGroups));
    ConfigSingleton.setChanged(this);
  }

  /**
   * Gets the authentication mechanisms contained in this configuration.
   *
   * @return The mechanisms as an immutable list.  The order is the same as was
   *     given when this configuration was created.
   */
  public synchronized ImmutableList<AuthnMechanism> getMechanisms() {
    return mechanisms;
  }

  /**
   * Gets the credential group for a given mechanism.
   *
   * @param mechanism The mechanism to get the credential group for.
   * @return The credential group for the given mechanism.
   * @throws IllegalArgumentException if the mechanism isn't contained in this
   *     configuration.
   */
  public CredentialGroup getCredentialGroup(AuthnMechanism mechanism) {
    for (CredentialGroup credentialGroup : getCredentialGroups()) {
      if (credentialGroup.getMechanisms().contains(mechanism)) {
        return credentialGroup;
      }
    }
    throw new IllegalArgumentException("Unknown mechanism: " + mechanism);
  }

  /**
   * Gets the credential group with a given name.
   *
   * @param name The credential-group name to search for.
   * @return The credential group with that name.
   * @throws IllegalArgumentException if there's no credential group with that name.
   */
  public CredentialGroup getCredentialGroup(String name) {
    Preconditions.checkNotNull(name);
    for (CredentialGroup credentialGroup : getCredentialGroups()) {
      if (name.equalsIgnoreCase(credentialGroup.getName())) {
        return credentialGroup;
      }
    }
    throw new IllegalArgumentException("No credential group with this name: " + name);
  }

  /**
   * Gets an authority predicate for a given credential group.
   *
   * @param credentialGroup A credential group to get the predicate for.
   * @return The authority predicate for the credential group.
   * @throws IllegalArgumentException if the credential group isn't contained in
   *     this configuration.
   */
  public Predicate<AuthnAuthority> getAuthorityPredicate(CredentialGroup credentialGroup) {
    ImmutableSet.Builder<AuthnAuthority> builder = ImmutableSet.builder();
    builder.add(credentialGroup.getAuthority());
    for (AuthnMechanism mechanism : credentialGroup.getMechanisms()) {
      builder.add(mechanism.getAuthority());
    }
    return Predicates.in(builder.build());
  }

  public synchronized FlexAuthorizer getFlexAuthorizer() {
    return flexAuthorizer;
  }

  /**
   * Sets this configurations's flex authorizer.  The security manager uses this
   * only for testing.
   */
  public void setFlexAuthorizer(FlexAuthorizer flexAuthorizer) {
    synchronized (this) {
      this.flexAuthorizer = flexAuthorizer;
    }
    ConfigSingleton.setChanged(this);
  }

  /**
   * @return The configuration parameters.
   */
  public synchronized ConfigParams getParams() {
    return params;
  }

  /** Contains the pair of mechanism name and mechanism. */
  public static class MechEntry<T extends AuthnMechanism> {
    String n;
    T mech;
    private MechEntry(String name, T mechanism) {
      n = name;
      mech = mechanism;
    } 
    public String getName() {
      return n;
    }
    public T getMech() {
      return mech;
    }
  }

  /**
   * Gets a list of credential group name and mechanism name pair for the mechanism.
   *
   * @param mechanismType the authentication mechanism type
   * @return a list of credential group name and mechanism name pair for the mechanism.
   */
  // @SuppressWarnings("unchecked")
  public <T extends AuthnMechanism> List<MechEntry<T>> getMechanism(final Class<T> mechanismType) {
    List<MechEntry<T>> mechanisms = Lists.newArrayList();
    for (CredentialGroup group : getCredentialGroups()) {
      for (AuthnMechanism mech : group.getMechanisms()) {
        if (mechanismType.isInstance(mech)) {
          mechanisms.add(new MechEntry(group.getName(), (T) mech));
        }
      }
    }
    return mechanisms;
  }

  /**
   * Gets a list of mechanisms for the mechanism type.
   *
   * @param mechanismType the authentication mechanism type
   * @return a list of mechanisms for the mechanism type.
   */
  @SuppressWarnings("unchecked")
  public <T extends AuthnMechanism> List<T> getMechanismList(
      final Class<T> mechanismType) {
    List<T> mechanisms = Lists.newArrayList();
    for (CredentialGroup group : getCredentialGroups()) {
      for (AuthnMechanism mech : group.getMechanisms()) {
        if (mechanismType.isInstance(mech)) {
          mechanisms.add((T) mech);
        }
      }
    }
    return mechanisms;
  }

  /**
   * Gets a key store for this server's certificate.
   *
   * @return A server-certificate key store.
   * @throws IOException if there are errors loading the store.
   * @throws GeneralSecurityException if there are security problems with the
   *     store.
   */
  @Nonnull
  public KeyStore getServerKeyStore()
      throws IOException, GeneralSecurityException {
    return SecurityManagerUtil.loadKeyStore(
        getServerKeyStoreFile(),
        getServerKeyStorePassword());
  }

  /**
   * Gets the file for this server's certificate key store.
   */
  @Nonnull
  public File getServerKeyStoreFile() {
    String filename = getServerCertificateFilename();
    Preconditions.checkNotNull(filename, "Server certificate filename is not configured.");
    return FileUtil.getContextFile(filename);
  }

  /**
   * Gets the password for this server's certificate key store.
   */
  @Nonnull
  public String getServerKeyStorePassword() {
    return "gsagsa";
  }

  /**
   * Gets a trust store of the configured certificate authorities.
   *
   * @return A CA certificate trust store.
   * @throws IOException if there are errors loading the store.
   * @throws GeneralSecurityException if there are security problems with the
   *     store.
   */
  @Nonnull
  public KeyStore getCacertsTrustStore()
      throws IOException, GeneralSecurityException {
    return SecurityManagerUtil.loadKeyStore(
        getCacertsTrustStoreFile(),
        getCacertsTrustStorePassword());
  }

  /**
   * Gets the file for the certificate-authority trust store.
   */
  @Nonnull
  public File getCacertsTrustStoreFile() {
    String filename = getCertificateAuthoritiesFilename();
    Preconditions.checkNotNull(filename, "CA certificates filename is not configured.");
    return FileUtil.getContextFile(filename);
  }

  /**
   * Gets the password for the certificate-authority trust store.
   */
  @Nonnull
  public String getCacertsTrustStorePassword() {
    return "gsagsa";
  }

  /**
   * Checks if the mechanism is configured.
   *
   * @param mechanismType the authentication mechanism type
   * @return true if the mechanism is already configured.
   */
  public <T extends AuthnMechanism> boolean hasMechanism(final Class<T> mechanismType) {
    return !getMechanism(mechanismType).isEmpty();
  }

  /**
   * Sets a configuration's parameters.  The security manager uses this only for
   * testing.
   *
   * @param params The new parameters.
   */
  public void setParams(ConfigParams params) {
    Preconditions.checkNotNull(params);
    synchronized (this) {
      this.params = params;
    }
    ConfigSingleton.setChanged(this);
  }

  /**
   * @return The name of the ACL group rules file, never null or empty.
   */
  public String getAclGroupsFilename() {
    return params.get(ParamName.ACL_GROUPS_FILENAME, String.class);
  }

  /**
   * @return The name of the ACL URL rules file, never null or empty.
   */
  public String getAclUrlsFilename() {
    return params.get(ParamName.ACL_URLS_FILENAME, String.class);
  }

  /**
   * Gets the groups file that came in via GDATA. 
   *
   * @return The name of the groups file, never null or empty.
   */
  public String getGdataGroupsFilename() {
    return params.get(ParamName.ACL_GROUPS_FILENAME, String.class);
  }

  /**
   * Gets the groups file that was fed to feedergate. 
   *
   * @return The name of the groups file, never null or empty.
   */
  public String getFedGroupsFilename() {
    return params.get(ParamName.GROUPS_FEED_FILENAME, String.class);
  }

  /**
   * @return The name of the certificate-authority certificates file, never null
   *     or empty.
   */
  public String getCertificateAuthoritiesFilename() {
    return params.get(ParamName.CERTIFICATE_AUTHORITIES_FILENAME, String.class);
  }

  /**
   * @return The boolean value whether to check the server certificate during
   *     serving time
   */
  public boolean getCheckServerCertificate() {
    return params.get(ParamName.CHECK_SERVER_CERTIFICATE, Boolean.class);
  }

  /**
   * @return The configured connector managers.
   */
  public ConnMgrInfo getConnectorManagerInfo() {
    return params.get(ParamName.CONNECTOR_MANAGER_INFO, ConnMgrInfo.class);
  }

  /**
   * @return The name of the http deny rules file, never null or empty.
   */
  public String getDenyRulesFilename() {
    return params.get(ParamName.DENY_RULES_FILENAME, String.class);
  }

  /**
   * @return The name of the proxy config file, never null or empty.
   */
  public String getProxyConfFilename() {
    return params.get(ParamName.PROXY_CONF_FILENAME, String.class);
  }

  /**
   * @return The name of the trust file, never null or empty.
   */
  public String getTrustFilename() {
    return params.get(ParamName.TRUST_FILENAME, String.class);
  }

  /**
   * @return The global batch request timeout.
   */
  public Float getGlobalBatchRequestTimeout() {
    return params.get(ParamName.GLOBAL_BATCH_REQUEST_TIMEOUT, Float.class);
  }

  /**
   * @return The global single request timeout.
   */
  public Float getGlobalSingleRequestTimeout() {
    return params.get(ParamName.GLOBAL_SINGLE_REQUEST_TIMEOUT, Float.class);
  }

  /**
   * @return The boolean value whether to do late binding during serving.
   */
  public boolean getLateBindingAcl() {
    return params.get(ParamName.LATE_BINDING_ACL, Boolean.class);
  }

  /**
   * @return The name of the SAML metadata configuration file, never null or
   *     empty.
   */
  public String getSamlMetadataFilename() {
    return params.get(ParamName.SAML_METADATA_FILENAME, String.class);
  }

  /**
   * @return The name of the security manager's certificate file, never null or
   *     empty.
   */
  public String getServerCertificateFilename() {
    return params.get(ParamName.SERVER_CERTIFICATE_FILENAME, String.class);
  }

  /**
   * @return The name of the certificate file to be used for signing outgoing
   *     messages, never null or empty.
   */
  public String getSigningCertificateFilename() {
    return params.get(ParamName.SIGNING_CERTIFICATE_FILENAME, String.class);
  }

  /**
   * @return The name of the key file to be used for signing outgoing messages,
   *     never null or empty.
   */
  public String getSigningKeyFilename() {
    return params.get(ParamName.SIGNING_KEY_FILENAME, String.class);
  }

  /**
   * @return The number of seconds a host remains "slow" after marked.
   */
  public int getSlowHostEmbargoPeriod() {
    return params.get(ParamName.SLOW_HOST_EMBARGO_PERIOD, Integer.class);
  }

  /**
   * @return The number of timeouts a host needs to be marked "slow".
   */
  public int getSlowHostNumberOfTimeouts() {
    return params.get(ParamName.SLOW_HOST_NUMBER_OF_TIMEOUTS, Integer.class);
  }

  /**
   * @return The period, in seconds, over which the timeouts are counted.
   */
  public int getSlowHostSamplePeriod() {
    return params.get(ParamName.SLOW_HOST_SAMPLE_PERIOD, Integer.class);
  }

  /**
   * @return True only if the slow-host tracker is enabled.
   */
  public boolean getSlowHostTrackerEnabled() {
    return params.get(ParamName.SLOW_HOST_TRACKER_ENABLED, Boolean.class);
  }

  /**
   * @return The size of the slow-host tracker cache.
   */
  public int getSlowHostTrackerSize() {
    return params.get(ParamName.SLOW_HOST_TRACKER_SIZE, Integer.class);
  }

  /**
   * @return The port of the stunnel service that is forwarding to the security manager.
   */
  public int getStunnelPort() {
    return params.get(ParamName.STUNNEL_PORT, Integer.class);
  }

  @Override
  public String toString() {
    return ConfigSingleton.getGson().toJson(this);
  }

  @Override
  public synchronized boolean equals(Object object) {
    if (object == this) { return true; }
    if (!(object instanceof SecurityManagerConfig)) { return false; }
    SecurityManagerConfig other = (SecurityManagerConfig) object;
    return Objects.equals(getVersion(), other.getVersion())
        && Objects.equals(getCredentialGroups(), other.getCredentialGroups())
        && Objects.equals(getParams(), other.getParams())
        && Objects.equals(getFlexAuthorizer(), other.getFlexAuthorizer());
  }

  @Override
  public synchronized int hashCode() {
    return Objects.hash(getVersion(), getCredentialGroups(), getParams(), getFlexAuthorizer());
  }

  static void registerTypeAdapters(GsonBuilder builder) {
    builder.registerTypeAdapter(SecurityManagerConfig.class,
        ProxyTypeAdapter.make(SecurityManagerConfig.class, LocalProxy.class));
    builder.registerTypeAdapter(new TypeToken<ImmutableList<CredentialGroup>>() {}.getType(),
        TypeAdapters.immutableList());
  }

  private static final class LocalProxy implements TypeProxy<SecurityManagerConfig> {
    int version;
    @SerializedName("CGs") ImmutableList<CredentialGroup> credentialGroups;
    ConfigParams params;
    @SerializedName("flexAuthz") FlexAuthorizer flexAuthorizer;

    @SuppressWarnings("unused")
    LocalProxy() {
    }

    @SuppressWarnings("unused")
    LocalProxy(SecurityManagerConfig config) {
      version = config.getVersion();
      credentialGroups = config.getCredentialGroups();
      params = config.getParams();
      flexAuthorizer = config.getFlexAuthorizer();
    }

    @Override
    public SecurityManagerConfig build() {
      return makeInternal(version, credentialGroups, params, flexAuthorizer);
    }
  }
}
