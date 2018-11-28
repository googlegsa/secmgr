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

package com.google.enterprise.secmgr.servlets;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.SamlSharedData;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;

/**
 * SamlServlet encapsulates the SAML-specific servlet extensions.  All SAML servlets
 * within the security manager are expected to extend this class.
 */
@Immutable
@ParametersAreNonnullByDefault
public abstract class SamlServlet extends ServletBase {

  @Nonnull private final SamlSharedData sharedData;

  protected SamlServlet(SamlSharedData sharedData) {
    Preconditions.checkNotNull(sharedData);
    this.sharedData = sharedData;
  }

  @Nonnull
  protected SamlSharedData getSharedData() {
    return sharedData;
  }

  @Nonnull
  protected String getLocalEntityId() {
    return sharedData.getLocalEntityId();
  }

  @Nonnull
  protected SAMLArtifactMap getArtifactMap() {
    return sharedData.getArtifactMap();
  }
  /**
   * Makes an OpenSAML message-context object and initializes it.
   *
   * @param <TI> The type of the request object.
   * @param <TO> The type of the response object.
   * @param <TN> The type of the name identifier used for subjects.`
   * @param request An HTTP request to specialize the metadata with.
   * @return A new message-context object.
   */
  @Nonnull
  public static <TI extends SAMLObject, TO extends SAMLObject, TN extends SAMLObject>
  SAMLMessageContext<TI, TO, TN> makeSamlMessageContext(HttpServletRequest request,
      SamlSharedData sharedData) throws IOException {
    return sharedData.makeSamlMessageContext(Metadata.getInstance(request));
  }

  @VisibleForTesting
  @Nonnull
  public <TI extends SAMLObject, TO extends SAMLObject, TN extends SAMLObject>
  SAMLMessageContext<TI, TO, TN> makeSamlMessageContext(Metadata metadata)
      throws IOException {
    return sharedData.makeSamlMessageContext(metadata);
  }


  /**
   * Initializes the peer entity components in an OpenSAML message-context
   * object.  Assumes the peer's entity ID has been decoded from a request
   * message.
   *
   * @param context A context to be initialized, which must have been generated
   *     by {@link SamlSharedData#makeSamlMessageContext}.
   * @param endpointType The type of the peer's endpoint.
   * @param binding The binding over which communication will occur.
   */
  public static void initializePeerEntity(SAMLMessageContext<?, ?, ?> context, QName endpointType,
      String binding, SamlSharedData sharedData)
      throws IOException {
    sharedData.initializePeerEntity(context, context.getInboundMessageIssuer(), endpointType,
        binding);
  }

  /**
   * Initializes the peer entity components in an OpenSAML message-context object.
   *
   * @param context A context to be initialized, which must have been generated
   *     by {@link SamlSharedData#makeSamlMessageContext}.
   * @param peerEntityId The entity ID of a peer.
   * @param endpointType The type of the peer's endpoint.
   * @param binding The binding over which communication will occur.
   */
  public void initializePeerEntity(SAMLMessageContext<?, ?, ?> context, String peerEntityId,
      QName endpointType, String binding)
      throws IOException {
    sharedData.initializePeerEntity(context, peerEntityId, endpointType, binding);
  }

}
