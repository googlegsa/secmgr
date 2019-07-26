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
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.Immutable;
import javax.xml.namespace.QName;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.saml.common.binding.impl.DefaultEndpointResolver;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLSelfEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.BindingCriterion;
import org.opensaml.saml.criterion.EndpointCriterion;
import org.opensaml.saml.criterion.RoleDescriptorCriterion;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.PDPDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.Credential;

/**
 * An object for sharing common information between the parts of a SAML IdP.
 */
@Immutable
@ParametersAreNonnullByDefault
public final class SamlSharedData {
  private static final Logger logger = Logger.getLogger(SamlSharedData.class.getName());
  public static final int DEFAULT_ARTIFACT_LIFETIME = 10 * 60 * 1000;  // ten minutes
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
        SAMLArtifactMap artifactMap = OpenSamlUtil.makeArtifactMap(DEFAULT_ARTIFACT_LIFETIME);
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
        OpenSamlUtil.makeArtifactMap(DEFAULT_ARTIFACT_LIFETIME),
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
   * @param metadata The metadata to use for initialization
   * @return A new message-context object.
   */
  @Nonnull
  public MessageContext<SAMLObject> makeSamlMessageContext(Metadata metadata)
      throws IOException {
    MessageContext<SAMLObject> context = OpenSamlUtil.makeSamlMessageContext();
    String localEntityId = getLocalEntityId();
    SAMLSelfEntityContext selfEntityContext =
        context.getSubcontext(SAMLSelfEntityContext.class, true);
    selfEntityContext.setEntityId(localEntityId);
    selfEntityContext.setRole(getLocalRoleDescriptorName());
    EntityDescriptor localEntity = metadata.getEntity(localEntityId);
    SAMLMetadataContext samlMetadataContext =
        context.getSubcontext(SAMLMetadataContext.class, true);
    samlMetadataContext.setEntityDescriptor(localEntity);
    samlMetadataContext.setRoleDescriptor(
        getRoleDescriptor(localEntity, getLocalRoleDescriptorName()));
    SAMLPeerEntityContext peerEntityContext =
        context.getSubcontext(SAMLPeerEntityContext.class, true);
    peerEntityContext.setRole(getPeerRoleDescriptorName());
    Metadata.MetadataContext metadataContext =
        context.getSubcontext(Metadata.MetadataContext.class, true);
    metadataContext.setMetadata(metadata);
    OpenSamlUtil.initializeSigningParameters(context, getSigningCredential());
    return context;
  }

  /**
   * Initializes the peer entity components in an OpenSAML message-context object.
   *
   * @param context A context to be initialized, which must have been generated by {@link
   *     #makeSamlMessageContext}.
   * @param peerEntityId The entity ID of a peer.
   * @param endpointType The type of the peer's endpoint.
   * @param binding The binding over which communication will occur.
   */
  public void initializePeerEntity(
      MessageContext<SAMLObject> context,
      String peerEntityId,
      QName endpointType,
      String binding)
      throws IOException {
    SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class);
    peerEntityContext.setEntityId(peerEntityId);
    Metadata.MetadataContext metadataContext =
        context.getSubcontext(Metadata.MetadataContext.class);
    EntityDescriptor peerEntity =
        Metadata.findEntity(peerEntityId, metadataContext.getMetadata().getResolver());
    if (peerEntity == null) {
      logger.info("No peer entity found for :" + peerEntityId);
      return;
    }
    SAMLMetadataContext peerEntityMetadataContext =
        peerEntityContext.getSubcontext(SAMLMetadataContext.class, true);
    peerEntityMetadataContext.setEntityDescriptor(peerEntity);
    RoleDescriptor roleDescriptor = getRoleDescriptor(peerEntity, getPeerRoleDescriptorName());
    peerEntityMetadataContext.setRoleDescriptor(roleDescriptor);
    SAMLEndpointContext endpointContext =
        peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
    setEndpoint(endpointType, binding, roleDescriptor, endpointContext);
  }

  private void setEndpoint(
      QName endpointType,
      String binding,
      RoleDescriptor roleDescriptor,
      SAMLEndpointContext endpointContext) {
    CriteriaSet criteria = new CriteriaSet();

    DefaultEndpointResolver<Endpoint> endpointResolver = new DefaultEndpointResolver<>();
    // Sample endpoint with binding only and EndpointCriterion with trust=false
    Endpoint sampleEndpoint =
        (Endpoint) OpenSamlUtil.makeSamlObjectBuilder(endpointType).buildObject(endpointType);
    sampleEndpoint.setBinding(binding);
    EndpointCriterion<Endpoint> endpointCriterion = new EndpointCriterion<>(sampleEndpoint, false);
    criteria.add(endpointCriterion);

    RoleDescriptorCriterion roleDescriptorCriterion = new RoleDescriptorCriterion(roleDescriptor);
    criteria.add(roleDescriptorCriterion);

    BindingCriterion bindingCriterion = new BindingCriterion(Arrays.asList(binding));
    criteria.add(bindingCriterion);

    try {
      endpointResolver.initialize();
      endpointContext.setEndpoint(endpointResolver.resolveSingle(criteria));
    } catch (ResolverException | ComponentInitializationException e) {
      // Safe to ignore
      logger.info("No endpoint found for peer binding: " + binding);
      return;
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
