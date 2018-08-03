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
package com.google.enterprise.secmgr.authzcontroller;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.inject.Singleton;

import java.io.IOException;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * A production implementation of an authorizer.
 */
@Singleton
@Immutable
@ParametersAreNonnullByDefault
public final class AuthorizerImpl implements Authorizer {
  private static final Logger logger = Logger.getLogger(AuthorizerImpl.class.getName());

  private final AuthorizationController controller;
  private final AuthnSessionManager sessionManager;

  @Inject
  private AuthorizerImpl(AuthorizationController controller, AuthnSessionManager sessionManager) {
    this.controller = controller;
    this.sessionManager = sessionManager;
  }

  @VisibleForTesting
  public static Authorizer getTestingInstance(AuthorizationController controller,
      AuthnSessionManager sessionManager) {
    Preconditions.checkNotNull(controller);
    Preconditions.checkNotNull(sessionManager);
    return new AuthorizerImpl(controller, sessionManager);
  }

  @Override
  public AuthzResult apply(Collection<Resource> resources, AuthnSession session,
      boolean enableFastAuthz) {
    if (session == null) {
      return AuthzResult.makeIndeterminate(Resource.resourcesToUrls(resources));
    }
    SessionSnapshot snapshot = session.getSnapshot();
    try {
      return controller.authorize(resources, snapshot, enableFastAuthz);
    } catch (IOException e) {
      logger.log(Level.WARNING, snapshot.logMessage("Error while authorizing: "), e);
      return AuthzResult.makeIndeterminate(Resource.resourcesToUrls(resources));
    }
  }
}
