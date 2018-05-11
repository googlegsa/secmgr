// Copyright 2008 Google Inc.
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
import com.google.common.base.Strings;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.Singleton;
import com.google.inject.TypeLiteral;
import com.google.inject.name.Named;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Observable;
import java.util.Observer;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;

/**
 * A singleton class to access configured parameters.
 */
@Singleton
@ThreadSafe
public class ConfigSingleton {
  private static final Logger logger = Logger.getLogger(ConfigSingleton.class.getName());

  @Inject private static Injector injector;
  @Inject private static ConfigSingleton instance;
  @GuardedBy("ConfigSingleton.class") private static SecurityManagerConfig configOverride = null;
  @GuardedBy("ConfigSingleton.class") private static Gson gson;
  private static final LocalObservable observable = new LocalObservable();

  private static final class LocalObservable extends Observable {
    @Override
    protected void setChanged() {
      super.setChanged();
    }
  }

  private final ConfigCodec configCodec;
  private final String configFilename;
  /** The modification time of the configuration file when last read. */
  @GuardedBy("this") private long configTime;
  /** The parsed configuration file. */
  @GuardedBy("this") private SecurityManagerConfig config;

  @Inject
  private ConfigSingleton(ConfigCodec configCodec, @Named("configFile") String configFilename) {
    Preconditions.checkNotNull(configCodec);
    Preconditions.checkArgument(!Strings.isNullOrEmpty(configFilename));
    this.configCodec = configCodec;
    this.configFilename = configFilename;
    logger.info("Config file " + configFilename);
    resetInternal();
  }

  /**
   * @return The application's Guice injector.
   */
  public static Injector getInjector() {
    return injector;
  }

  /**
   * A convenience method that invokes the injector.
   *
   * @param clazz The class to instantiate.
   * @return An instance of the given class.
   */
  public static <T> T getInstance(Class<T> clazz) {
    return injector.getInstance(clazz);
  }

  /**
   * A convenience method that invokes the injector.
   *
   * @param type The type to instantiate.
   * @return An instance of the given type.
   */
  public static <T> T getInstance(TypeLiteral<T> type) {
    return injector.getInstance(Key.get(type));
  }

  @VisibleForTesting
  public static synchronized void reset() {
    configOverride = null;
    instance.resetInternal();
  }

  private synchronized void resetInternal() {
    configTime = 0;
    config = null;
  }

  /**
   * Adds an observer that's notified of config changes.
   */
  public static void addObserver(Observer observer) {
    observable.addObserver(observer);
  }

  /**
   * Deletes an observer that's notified of config changes.
   */
  public static void deleteObserver(Observer observer) {
    observable.deleteObserver(observer);
  }

  static void setChanged(SecurityManagerConfig config) {
    observable.setChanged();
    observable.notifyObservers(config);
  }

  public static synchronized void setGsonRegistrations(GsonRegistrations registrations) {
    GsonBuilder builder = new GsonBuilder();
    builder.setPrettyPrinting();
    registrations.register(builder);
    gson = builder.create();
  }

  /** A type to use for passing in Gson registrations. */
  public interface GsonRegistrations {
    public void register(GsonBuilder builder);
  }

  public static synchronized Gson getGson() {
    Preconditions.checkNotNull(gson);
    return gson;
  }

  /**
   * @return The current configuration.
   * @throws IOException if there are I/O errors reading the configuration.
   */
  public static synchronized SecurityManagerConfig getConfig()
      throws IOException {
    return (configOverride != null) ? configOverride : getConfigNoOverride();
  }

  @VisibleForTesting
  public static synchronized SecurityManagerConfig getConfigNoOverride()
      throws IOException {
    return instance.getConfigInternal();
  }

  @VisibleForTesting
  public static synchronized void setConfig(SecurityManagerConfig config) {
    configOverride = config;
    setChanged(config);
  }

  private synchronized SecurityManagerConfig getConfigInternal()
      throws IOException {
    logger.fine("About to read config " + configFilename);

    File file = FileUtil.getContextFile(configFilename);
    // Check the config file's mod time; if it hasn't changed since the last
    // successful read, use the cached value.  Otherwise, try reading the config
    // file.  Go around the loop until the mod time before the read and the mod
    // time after the read are the same.  This detects changes to the file
    // during the read.
    boolean changed = false;
    while (true) {
      long time = file.lastModified();
      if (time == 0) {
        throw new IOException("No such file: " + file);
      }
      if (time == configTime) {
        break;
      }
      try {
        config = configCodec.readConfig(file);
      } catch (ConfigException e) {
        logger.log(Level.SEVERE, "Error parsing config file. Returning default config.", e);
        config = SecurityManagerConfig.makeDefault();
      }
      configTime = time;
      changed = true;
    }
    if (changed) {
      setChanged(config);
    }

    logger.fine("Read config");
    return config;
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
  public static KeyStore getServerKeyStore()
      throws IOException, GeneralSecurityException {
    return getConfig().getServerKeyStore();
  }

  /**
   * Gets the file for this server's certificate key store.
   */
  @Nonnull
  public static File getServerKeyStoreFile()
      throws IOException {
    return getConfig().getServerKeyStoreFile();
  }

  /**
   * Gets the password for this server's certificate key store.
   */
  @Nonnull
  public static String getServerKeyStorePassword()
      throws IOException {
    return getConfig().getServerKeyStorePassword();
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
  public static KeyStore getCacertsTrustStore()
      throws IOException, GeneralSecurityException {
    return getConfig().getCacertsTrustStore();
  }

  @Nonnull
  public static File getCacertsTrustStoreFile()
      throws IOException {
    return getConfig().getCacertsTrustStoreFile();
  }

  @Nonnull
  public static String getCacertsTrustStorePassword()
      throws IOException {
    return getConfig().getCacertsTrustStorePassword();
  }

  /** @see SecurityManagerConfig#getAclGroupsFilename */
  public static String getAclGroupsFilename() throws IOException {
    return getConfig().getAclGroupsFilename();
  }

  /** @see SecurityManagerConfig#getAclUrlsFilename */
  public static String getAclUrlsFilename() throws IOException {
    return getConfig().getAclUrlsFilename();
  }

  /** @see SecurityManagerConfig#getGdataGroupsFilename */
  public static String getGdataGroupsFilename() throws IOException {
    return getConfig().getGdataGroupsFilename();
  }

  /** @see SecurityManagerConfig#getFedGroupsFilename */
  public static String getFedGroupsFilename() throws IOException {
    return getConfig().getFedGroupsFilename();
  }

  /** @see SecurityManagerConfig#getCertificateAuthoritiesFilename */
  public static String getCertificateAuthoritiesFilename() throws IOException {
    return getConfig().getCertificateAuthoritiesFilename();
  }

  /** @see SecurityManagerConfig#getCheckServerCertificate */
  public static boolean getCheckServerCertificate() throws IOException {
    return getConfig().getCheckServerCertificate();
  }

  /** @see SecurityManagerConfig#getConnectorManagerInfo */
  public static ConnMgrInfo getConnectorManagerInfo() throws IOException {
    return getConfig().getConnectorManagerInfo();
  }

  /** @see SecurityManagerConfig#getDenyRulesFilename */
  public static String getDenyRulesFilename() throws IOException {
    return getConfig().getDenyRulesFilename();
  }

  /** @see SecurityManagerConfig#getTrustFilename */
  public static String getTrustFilename() throws IOException {
    return getConfig().getTrustFilename();
  }

  /** @see SecurityManagerConfig#getGlobalBatchRequestTimeout */
  public static Float getGlobalBatchRequestTimeout() throws IOException {
    return getConfig().getGlobalBatchRequestTimeout();
  }

  /** @see SecurityManagerConfig#getGlobalSingleRequestTimeout */
  public static Float getGlobalSingleRequestTimeout() throws IOException {
    return getConfig().getGlobalSingleRequestTimeout();
  }

  /** @see SecurityManagerConfig#getLateBindingAcl */
  public static boolean getLateBindingAcl() throws IOException {
    return getConfig().getLateBindingAcl();
  }

  /** @see SecurityManagerConfig#getSamlMetadataFilename */
  public static String getSamlMetadataFilename() throws IOException {
    return getConfig().getSamlMetadataFilename();
  }

  /** @see SecurityManagerConfig#getServerCertificateFilename */
  public static String getServerCertificateFilename() throws IOException {
    return getConfig().getServerCertificateFilename();
  }

  /** @see SecurityManagerConfig#getSigningCertificateFilename */
  public static String getSigningCertificateFilename() throws IOException {
    return getConfig().getSigningCertificateFilename();
  }

  /** @see SecurityManagerConfig#getSigningKeyFilename */
  public static String getSigningKeyFilename() throws IOException {
    return getConfig().getSigningKeyFilename();
  }

  /** @see SecurityManagerConfig#getStunnelPort */
  public static int getStunnelPort() throws IOException {
    return getConfig().getStunnelPort();
  }
}
