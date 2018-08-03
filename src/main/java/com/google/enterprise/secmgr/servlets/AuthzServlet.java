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
package com.google.enterprise.secmgr.servlets;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import com.google.enterprise.secmgr.authzcontroller.Authorizer;
import com.google.enterprise.secmgr.common.AuthzMessages;
import com.google.enterprise.secmgr.common.AuthzMessages.AuthzRequest;
import com.google.enterprise.secmgr.common.AuthzMessages.AuthzResponse;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.inject.Singleton;

import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * An authorization service that uses protocol-buffer messages.
 */
@Singleton
@Immutable
@ParametersAreNonnullByDefault
public class AuthzServlet extends ServletBase implements PostableHttpServlet {
  private static final Logger logger = Logger.getLogger(AuthzServlet.class.getName());

  private final Authorizer authorizer;
  private final AuthnSessionManager sessionManager;

  @Inject
  private AuthzServlet(Authorizer authorizer, AuthnSessionManager sessionManager) {
    logger.info("Init authz servlet");
    this.authorizer = authorizer;
    this.sessionManager = sessionManager;
  }

  @VisibleForTesting
  static AuthzServlet getTestingInstance(Authorizer authorizer, AuthnSessionManager sessionManager) {
    Preconditions.checkNotNull(authorizer);
    return new AuthzServlet(authorizer, sessionManager);
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    logger.info("Got authz request");
    AuthzRequest authzRequest = AuthzRequest.parseFrom(request.getInputStream());

    AuthzResult result
        = authorizer.apply(
            getResources(authzRequest),
            sessionManager.getSession(authzRequest.getSubject()),
            authzRequest.getMode() == AuthzRequest.Mode.FAST);

    AuthzResponse.Builder builder = AuthzResponse.newBuilder();

    // Return the result in the same order as in the AuthzRequest.
    for (AuthzRequest.Resource resource : authzRequest.getResourceList()) {
      String id = resource.getIdentifier();
      AuthzStatus status = result.get(id);
      builder.addResource(makeResource(id, (status == null) ? AuthzStatus.INDETERMINATE : status));
    }
    AuthzResponse authzResponse = builder.build();

    OutputStream output
        = initRawResponseWithHeaders(response, HttpServletResponse.SC_OK,
            HttpUtil.TYPE_OCTET_STREAM);
    try {
      authzResponse.writeTo(output);
      logger.info("Sent authz response");
    } finally {
      output.close();
    }
  }

  @Nonnull
  @VisibleForTesting
  static ImmutableList<Resource> getResources(AuthzRequest authzRequest) {
    ImmutableList.Builder<Resource> builder = ImmutableList.builder();
    for (AuthzRequest.Resource resource : authzRequest.getResourceList()) {
      builder.add(
          new Resource(
              resource.getIdentifier(),
              getEarlyDecision(resource)));
    }
    return builder.build();
  }

  @Nonnull
  private static AuthzStatus getEarlyDecision(AuthzRequest.Resource resource) {
    return resource.hasEarlyDecision()
        ? decodeDecision(resource.getEarlyDecision())
        : null;
  }

  @Nonnull
  private static AuthzResponse.Resource makeResource(String identifier,
      AuthzStatus decision) {
    return AuthzResponse.Resource.newBuilder()
        .setIdentifier(identifier)
        .setDecision(encodeDecision(decision))
        .build();
  }

  @Nonnull
  public static AuthzStatus decodeDecision(AuthzMessages.AuthzStatus decision) {
    switch (decision) {
      case PERMIT: return AuthzStatus.PERMIT;
      case DENY: return AuthzStatus.DENY;
      case INDETERMINATE: return AuthzStatus.INDETERMINATE;
      default: throw new IllegalStateException("Unknown value: " + decision);
    }
  }

  @Nonnull
  public static AuthzMessages.AuthzStatus encodeDecision(AuthzStatus decision) {
    switch (decision) {
      case PERMIT: return AuthzMessages.AuthzStatus.PERMIT;
      case DENY: return AuthzMessages.AuthzStatus.DENY;
      case INDETERMINATE: return AuthzMessages.AuthzStatus.INDETERMINATE;
      default: throw new IllegalStateException("Unknown value: " + decision);
    }
  }
}
