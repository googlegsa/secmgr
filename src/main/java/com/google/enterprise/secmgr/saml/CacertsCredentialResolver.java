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
package com.google.enterprise.secmgr.saml;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.impl.AbstractCriteriaFilteringCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.x509.BasicX509Credential;

/**
 * A credential resolver that produces all of the certificates in a CA
 * certificates trust store.
 */
@Immutable
@ParametersAreNonnullByDefault
public class CacertsCredentialResolver extends AbstractCriteriaFilteringCredentialResolver {
  private static final Logger logger = Logger.getLogger(CacertsCredentialResolver.class.getName());

  @Nonnull private final KeyStore trustStore;

  private CacertsCredentialResolver(KeyStore trustStore) {
    super();
    this.trustStore = trustStore;
  }

  /**
   * Makes a CA certificates credential resolver.
   *
   * @param trustStore A trust store containing the CA certificates.
   * @return A corresponding credential resolver.
   */
  @Nonnull
  public static CacertsCredentialResolver make(KeyStore trustStore) {
    Preconditions.checkNotNull(trustStore);
    return new CacertsCredentialResolver(trustStore);
  }

  @Override
  protected Iterable<Credential> resolveFromSource(CriteriaSet criteriaSet)
      throws SecurityException {

    EntityIdCriterion entityIdCriterion = criteriaSet.get(EntityIdCriterion.class);
    if (entityIdCriterion == null) {
      logger.warning("Unable to process CA certs without entity ID.");
      return ImmutableList.of();
    }
    String entityId = entityIdCriterion.getEntityId();

    UsageCriterion usageCriterion = criteriaSet.get(UsageCriterion.class);
    UsageType usageType =
        (usageCriterion != null) ? usageCriterion.getUsage() : UsageType.UNSPECIFIED;
    if (!(usageType == UsageType.SIGNING || usageType == UsageType.UNSPECIFIED)) {
      logger.info("Not processing CA certs because this isn't a signing request.");
      return ImmutableList.of();
    }

    ImmutableList.Builder<Credential> builder = ImmutableList.builder();
    try {
      Enumeration<String> aliases = trustStore.aliases();
      while (aliases.hasMoreElements()) {
        String alias = aliases.nextElement();
        if (trustStore.entryInstanceOf(alias, KeyStore.TrustedCertificateEntry.class)) {
          KeyStore.TrustedCertificateEntry entry
              = (KeyStore.TrustedCertificateEntry) trustStore.getEntry(alias, null);
          X509Certificate certificate = (X509Certificate) entry.getTrustedCertificate();
          BasicX509Credential credential = new BasicX509Credential(certificate);
          credential.setEntityId(entityId);
          credential.setUsageType(UsageType.SIGNING);
          credential.setEntityCertificateChain(ImmutableList.of(certificate));
          builder.add(credential);
        }
      }
    } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
      lose(e);
    }
    return builder.build();
  }

  private static void lose(Exception e)
      throws SecurityException {
    String message = "Exception while processing CA certs: ";
    logger.warning(message + e.getMessage());
    throw new SecurityException(message, e);
  }
}
