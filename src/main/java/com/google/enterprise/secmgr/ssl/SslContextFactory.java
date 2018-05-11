/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.enterprise.secmgr.ssl;

import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Observable;
import java.util.Observer;
import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.Immutable;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * A factory that generates {@link SSLContext} instances for the GSA's credentials.
 */
@Immutable
@ParametersAreNonnullByDefault
public final class SslContextFactory {
  public static final Logger logger = Logger.getLogger(SslContextFactory.class.getName());

  @GuardedBy("SslContextFactory.class") private static SslContextFactory instance = null;
  static {
    ConfigSingleton.addObserver(
        new Observer() {
          @Override
          public void update(Observable observable, Object argument) {
            synchronized (SslContextFactory.class) {
              instance = null;
            }
          }
        });
  }

  @Nullable private final KeyStore serverKeyStore;
  @Nullable private final String serverKeyStorePassword;
  @Nullable private final KeyStore cacertsTrustStore;
  private final boolean checkServerCertificate;

  private SslContextFactory(@Nullable KeyStore serverKeyStore,
      @Nullable String serverKeyStorePassword, @Nullable KeyStore cacertsTrustStore,
      boolean checkServerCertificate) {
    this.serverKeyStore = serverKeyStore;
    this.serverKeyStorePassword = serverKeyStorePassword;
    this.cacertsTrustStore = cacertsTrustStore;
    this.checkServerCertificate = checkServerCertificate;
  }

  private static synchronized SslContextFactory getInstance() {
    if (instance == null) {
      try {
        instance = make(ConfigSingleton.getConfig());
      } catch (IOException e) {
        throw new IllegalStateException("Unable to load config: ", e);
      }
    }
    return instance;
  }

  private static SslContextFactory make(SecurityManagerConfig config) {
    KeyStore serverKeyStore;
    try {
      serverKeyStore = config.getServerKeyStore();
    } catch (IOException e) {
      logger.warning("Unable to get server key: " + e.getMessage());
      serverKeyStore = null;
    } catch (GeneralSecurityException e) {
      logger.warning("Unable to get server key: " + e.getMessage());
      serverKeyStore = null;
    }
    KeyStore cacertsTrustStore;
    try {
      cacertsTrustStore = config.getCacertsTrustStore();
    } catch (IOException e) {
      logger.warning("Unable to get CA certificates: " + e.getMessage());
      cacertsTrustStore = null;
    } catch (GeneralSecurityException e) {
      logger.warning("Unable to get CA certificates: " + e.getMessage());
      cacertsTrustStore = null;
    }
    return new SslContextFactory(
        serverKeyStore,
        config.getServerKeyStorePassword(),
        cacertsTrustStore,
        config.getCheckServerCertificate());
  }

  /**
   * Gets an SSL context instance.
   */
  @Nonnull
  public static SSLContext createContext() {
    return getInstance().createContextInternal();
  }

  /**
   * Gets an SSL socket factory.
   */
  @Nonnull
  public static SSLSocketFactory getSocketFactory() {
    return createContext().getSocketFactory();
  }

  private SSLContext createContextInternal() {
    try {
      SSLContext sslcontext = SSLContext.getInstance("SSL");
      sslcontext.init(createKeyManagers(), createTrustManagers(), null);
      return sslcontext;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private KeyManager[] createKeyManagers() {
    if (serverKeyStore == null) {
      logger.fine("No server key store available");
      return null;
    }
    try {
      Enumeration<String> aliases = serverKeyStore.aliases();
      for (int i = 1; aliases.hasMoreElements(); i += 1) {
        String alias = aliases.nextElement();
        Certificate[] certificates = serverKeyStore.getCertificateChain(alias);
        if (certificates != null) {
          logger.fine("Certificate chain '" + alias + "':");
          for (Certificate certificate : certificates) {
            if (certificate instanceof X509Certificate) {
              X509Certificate cert = (X509Certificate) certificate;
              logger.fine(" Certificate " + i + ":");
              logger.fine("  Subject DN: " + cert.getSubjectDN());
              logger.fine("  Signature Algorithm: " + cert.getSigAlgName());
              logger.fine("  Valid from: " + cert.getNotBefore());
              logger.fine("  Valid until: " + cert.getNotAfter());
              logger.fine("  Issuer: " + cert.getIssuerDN());
            }
          }
        }
      }
      logger.fine("Initializing key manager");
      KeyManagerFactory factory
          = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      factory.init(serverKeyStore,
          (serverKeyStorePassword != null) ? serverKeyStorePassword.toCharArray() : null);
      return factory.getKeyManagers();
    } catch (GeneralSecurityException e) {
      logger.warning("Error generating key managers: " + e.getMessage());
      return null;
    }
  }

  private TrustManager[] createTrustManagers() {
    if (cacertsTrustStore == null) {
      logger.fine("No CA certs available");
      return null;
    }
    if (!checkServerCertificate) {
      logger.fine("Using dummy trust manager: accept any server certificate.");
      return new TrustManager[] { new DummyTrustManager() };
    }
    try {
      Enumeration<String> aliases = cacertsTrustStore.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        logger.fine("Trusted certificate '" + alias + "':");
        Certificate trustedcert = cacertsTrustStore.getCertificate(alias);
        if (trustedcert != null && trustedcert instanceof X509Certificate) {
          X509Certificate cert = (X509Certificate) trustedcert;
          logger.fine("  Subject DN: " + cert.getSubjectDN());
          logger.fine("  Signature Algorithm: " + cert.getSigAlgName());
          logger.fine("  Valid from: " + cert.getNotBefore());
          logger.fine("  Valid until: " + cert.getNotAfter());
          logger.fine("  Issuer: " + cert.getIssuerDN());
        }
      }
      logger.fine("Initializing trust manager");
      TrustManagerFactory factory
          = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      factory.init(cacertsTrustStore);
      return factory.getTrustManagers();
    } catch (GeneralSecurityException e) {
      logger.warning("Error generating trust managers: " + e.getMessage());
      return null;
    }
  }

  private static final class DummyTrustManager implements X509TrustManager {
    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return null;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certs, String authType) {
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certs, String authType) {
    }
  }
}
