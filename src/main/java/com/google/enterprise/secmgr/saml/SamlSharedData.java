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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicEndpointSelector;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.PDPDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.security.credential.Credential;

import java.io.IOException;
import java.util.List;
import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.Immutable;
import javax.xml.namespace.QName;

/**
 * An object for sharing common information between the parts of a SAML IdP.
 */
@Immutable
@ParametersAreNonnullByDefault
public final class SamlSharedData {
  private static final Logger logger = Logger.getLogger(SamlSharedData.class.getName());
  public static final int DEFAULT_ARTIFACT_LIFETIME_MS = 10 * 60 * 1000;  // ten minutes
  public static final ImmutableList<String> ALLOWED_BINDINGS
      = ImmutableList.of(
          SAMLConstants.SAML2_ARTIFACT_BINDING_URI,
          SAMLConstants.SAML2_POST_BINDING_URI);
  private static final Object PRODUCTION_INSTANCES_LOCK = new Object();
  @GuardedBy("PRODUCTION_INSTANCES_LOCK")
  private static ImmutableMap<Role, SamlSharedData> productionInstances;

  /**
   * The role being played by the entity associated with a shared-data instance.
   */
  public enum Role { SERVICE_PROVIDER, IDENTITY_PROVIDER, AUTHZ_CLIENT, AUTHZ_SERVER }

  @Nonnull private final String localEntityId;
  @Nonnull private final Role role;
  @Nonnull private final SAMLArtifactMap artifactMap;
  @Nullable private final Supplier<Credential> signingCredentialSupplier;

  private SamlSharedData(String localEntityId, Role role, SAMLArtifactMap artifactMap,
      @Nullable Supplier<Credential> signingCredentialSupplier) {
    this.localEntityId = localEntityId;
    this.role = role;
    this.artifactMap = artifactMap;
    this.signingCredentialSupplier = signingCredentialSupplier;
  }

  /**
   * Gets a production instance for a particular role.
   *
   * @param role The role for this instance.
   * @return The unique production instance for the given role.
   */
  @Nonnull
  public static SamlSharedData getProductionInstance(Role role) {
    Preconditions.checkNotNull(role);
    initialize();
    synchronized (PRODUCTION_INSTANCES_LOCK) {
      return productionInstances.get(role);
    }
  }

  private static void initialize() {
    synchronized (PRODUCTION_INSTANCES_LOCK) {
      if (productionInstances == null) {
        String entityId = Metadata.getSmEntityId();
        Supplier<Credential> supplier = new ProductionSigningCredentialSupplier();
        SAMLArtifactMap artifactMap = OpenSamlUtil.makeArtifactMap(DEFAULT_ARTIFACT_LIFETIME_MS);
        ImmutableMap.Builder<Role, SamlSharedData> builder = ImmutableMap.builder();
        for (Role role : Role.values()) {
          builder.put(role, new SamlSharedData(entityId, role, artifactMap, supplier));
        }
        productionInstances = builder.build();
      }
    }
  }

  private static final class ProductionSigningCredentialSupplier implements Supplier<Credential> {
    @Override
    public Credential get() {
      try {
        SecurityManagerConfig config = ConfigSingleton.getConfig();
        return OpenSamlUtil.readX509Credential(
            FileUtil.getContextFile(config.getSigningCertificateFilename()),
            FileUtil.getContextFile(config.getSigningKeyFilename()));
      } catch (IOException e) {
        logger.warning("Exception while reading X.509 credential: " + e.getMessage());
        return null;
      }
    }
  }

  /**
   * Gets a shared-data object with a given signing credential.
   *
   * @param localEntityId A SAML entity ID for the local entity.
   * @param role The role for this instance.
   * @param signingCredentialSupplier A supplier that generates a signing credential.
   * @return An appropriate shared-data object.
   */
  @VisibleForTesting
  @Nonnull
  public static SamlSharedData make(String localEntityId, Role role,
      @Nullable Supplier<Credential> signingCredentialSupplier) {
    Preconditions.checkNotNull(localEntityId);
    Preconditions.checkNotNull(role);
    return new SamlSharedData(localEntityId, role,
        OpenSamlUtil.makeArtifactMap(DEFAULT_ARTIFACT_LIFETIME_MS),
        signingCredentialSupplier);
  }

  /**
   * Gets the local entity ID.
   */
  @Nonnull
  public String getLocalEntityId() {
    return localEntityId;
  }

  /**
   * Gets the local role.
   */
  @Nullable
  public Role getRole() {
    return role;
  }

  /**
   * Gets the artifact map to use when responding with the artifact binding.
   */
  @Nonnull
  public SAMLArtifactMap getArtifactMap() {
    return artifactMap;
  }

  /**
   * Gets the role-descriptor element name for the local entity.
   */
  @Nullable
  public QName getLocalRoleDescriptorName() {
    switch (role) {
      case SERVICE_PROVIDER: return SPSSODescriptor.DEFAULT_ELEMENT_NAME;
      case IDENTITY_PROVIDER: return IDPSSODescriptor.DEFAULT_ELEMENT_NAME;
      case AUTHZ_CLIENT: return null;
      case AUTHZ_SERVER: return PDPDescriptor.DEFAULT_ELEMENT_NAME;
      default: throw new IllegalStateException();
    }
  }

  /**
   * Gets the role-descriptor element name for the peer entity.
   */
  @Nullable
  public QName getPeerRoleDescriptorName() {
    switch (role) {
      case SERVICE_PROVIDER: return IDPSSODescriptor.DEFAULT_ELEMENT_NAME;
      case IDENTITY_PROVIDER: return SPSSODescriptor.DEFAULT_ELEMENT_NAME;
      case AUTHZ_CLIENT: return PDPDescriptor.DEFAULT_ELEMENT_NAME;
      case AUTHZ_SERVER: return null;
      default: throw new IllegalStateException();
    }
  }

  /**
   * Makes an OpenSAML message-context object and initializes it.
   *
   * @param <TI> The type of the request object.
   * @param <TO> The type of the response object.
   * @param <TN> The type of the name identifier used for subjects.
   * @param metadata The metadata to use for initialization
   * @return A new message-context object.
   */
  @Nonnull
  public <TI extends SAMLObject, TO extends SAMLObject, TN extends SAMLObject>
        SAMLMessageContext<TI, TO, TN> makeSamlMessageContext(Metadata metadata)
      throws IOException {
    SAMLMessageContext<TI, TO, TN> context = OpenSamlUtil.makeSamlMessageContext();
    context.setMetadataProvider(metadata.getProvider());
    String localEntityId = getLocalEntityId();
    EntityDescriptor localEntity = metadata.getEntity(localEntityId);
    context.setLocalEntityId(localEntityId);
    context.setLocalEntityMetadata(localEntity);
    context.setOutboundMessageIssuer(localEntityId);
    QName localRoleDescriptorName = getLocalRoleDescriptorName();
    context.setLocalEntityRole(localRoleDescriptorName);
    context.setLocalEntityRoleMetadata(getRoleDescriptor(localEntity, localRoleDescriptorName));
    context.setPeerEntityRole(getPeerRoleDescriptorName());
    context.setOutboundSAMLMessageSigningCredential(getSigningCredential());
    return context;
  }

  /**
   * Initializes the peer entity components in an OpenSAML message-context object.
   *
   * @param context A context to be initialized, which must have been generated
   *     by {@link #makeSamlMessageContext}.
   * @param peerEntityId The entity ID of a peer.
   * @param endpointType The type of the peer's endpoint.
   * @param binding The binding over which communication will occur.
   */
  public void initializePeerEntity(SAMLMessageContext<?, ?, ?> context, String peerEntityId,
      QName endpointType, String binding)
      throws IOException {
    context.setPeerEntityId(peerEntityId);
    EntityDescriptor peerEntity = Metadata.findEntity(peerEntityId, context.getMetadataProvider());
    if (peerEntity == null) {
      logger.info("No peer entity found for :" + peerEntityId);
      return;
    }
    context.setPeerEntityMetadata(peerEntity);
    RoleDescriptor roleDescriptor = getRoleDescriptor(peerEntity, getPeerRoleDescriptorName());
    context.setPeerEntityRoleMetadata(roleDescriptor);
    {
      BasicEndpointSelector selector = new BasicEndpointSelector();
      selector.setEntityMetadata(peerEntity);
      selector.setEndpointType(endpointType);
      selector.setEntityRoleMetadata(roleDescriptor);
      selector.getSupportedIssuerBindings().add(binding);
      context.setPeerEntityEndpoint(selector.selectEndpoint());
    }
  }

  private RoleDescriptor getRoleDescriptor(EntityDescriptor entity, QName name) {
    if (name == null) {
      return null;
    }
    List<RoleDescriptor> roles = entity.getRoleDescriptors(name, SAMLConstants.SAML20P_NS);
    return roles.isEmpty() ? null : roles.get(0);
  }

  private Credential getSigningCredential() {
    return (signingCredentialSupplier != null)
        ? signingCredentialSupplier.get()
        : null;
  }
}
