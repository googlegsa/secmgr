/*
 * Copyright 2013 Google Inc.
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
import com.google.common.base.Strings;
import com.google.enterprise.common.StringLockManager;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import com.google.enterprise.secmgr.authncontroller.ExportedState;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.authncontroller.TrustManager;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
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
 * An authentication service for secure search API.
 */
@Singleton
@Immutable
@ParametersAreNonnullByDefault
public class AuthnServlet extends ServletBase implements PostableHttpServlet {
  private static final Logger logger = Logger.getLogger(AuthnServlet.class.getName());

  static final String GSA_USER_NAME = "X_GSA_USER";
  static final String GSA_PASSWORD = "X_GSA_PASSWORD";
  static final String GSA_CREDENTIAL_GROUP = "X_GSA_CREDENTIAL_GROUP";

  @Nonnull private final AuthnSessionManager sessionManager;
  @Nonnull private final AuthnController controller;
  @Nonnull private final TrustManager trustManager;
  @Nonnull private final StringLockManager usernameLockManager;

  @Inject
  public AuthnServlet(AuthnSessionManager sessionManager) {
    controller = ConfigSingleton.getInstance(AuthnController.class);
    trustManager = ConfigSingleton.getInstance(TrustManager.class);
    usernameLockManager = new StringLockManager();
    this.sessionManager = sessionManager;
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    AuthnSession.setSecureSearchApiMode(true);
    AuthnSession session = sessionManager.createSession();
    session.setRequest(request);

    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    if (session == null) {
      logger.warning("Could not get session; Something wrong with EFE.");
      return;
    }

    Decorator decorator = SessionUtil.getLogDecorator(session.getSessionId());

    session.logIncomingRequest(request);

    SessionSnapshot snapshot = session.getSnapshot();
    if (!snapshot.getView().isVerified()) {
      synchronized (session) {
        boolean success = false;
        session.setStateAuthenticating();

        controller.setSecureSearchApiMode(true);
        switch (controller.authenticate(session, request, response)) {
          case SUCCESSFUL:
            // Generate a successful response.
            session.getSnapshot();
            session.setStateIdle();
            success = true;
            break;

          case UNSUCCESSFUL:
            // Generate an unsuccessful response.
            initErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            session.setStateIdle();
            break;

          case UNFINISHED:
            // The response was set up by the back end.
            break;

          default:
            throw new IllegalStateException("Unknown AuthnResult value");
        }

        if (!success) {
          logger.info("Failed to authenticate app");
          return;
        }

        logger.info("Succeeded to authenticate app");

        snapshot = session.getSnapshot();
      }
    }
    // Check if it's trusted user. If it is , create a session for the end user
    ExportedState state = ExportedState.make(snapshot);

    AuthnSession userSession = null;
    String endUser = request.getHeader(GSA_USER_NAME);
    String password = request.getHeader(GSA_PASSWORD);
    String namespace = request.getHeader(GSA_CREDENTIAL_GROUP);
    if (!Strings.isNullOrEmpty(endUser)) {
      logger.fine("Got user from header " + endUser);

      if (!trustManager.isTrusted(state)) {
        logger.info("Untrusted user can not delegate others");
        return;
      }
      Object usernameLock = usernameLockManager.acquire(endUser);
      try {
        synchronized (usernameLock) {
          userSession = sessionManager.createPersistentSession(request);
          userSession.addCredentials(endUser, namespace, password);
        }
      } catch (IOException e) {
        logger.warning(decorator.apply("Could not get/make end user session: session manager"));
        return;
      } catch (IllegalArgumentException e1) {
        logger.warning(decorator.apply("Could not get/make end user session. Illegal user "
              + endUser + " or credential group " + namespace));
        return;
      } finally {
        usernameLockManager.release(endUser);
      }

      if (userSession == null) {
        logger.warning(decorator.apply("Could not get/make end user session"));
        return;
      }
      synchronized (userSession) {
        userSession.setRequestId(SessionUtil.findGsaRequestId(request));
        decorator = SessionUtil.getLogDecorator(userSession.getSessionId());
        userSession.logIncomingRequest(request);

        logger.info("Created session for user " + endUser);
        boolean success = false;
        userSession.setStateAuthenticating();

        switch (controller.authenticate(userSession, null, response)) {
          case SUCCESSFUL:
            // Generate a successful response.
            userSession.getSnapshot();
            userSession.setStateIdle();
            success = true;
            break;

          case UNSUCCESSFUL:
            // Generate an unsuccessful response.
            initErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            userSession.setStateIdle();
            break;

          case UNFINISHED:
            // The response was set up by the back end.
            break;

          default:
            throw new IllegalStateException("Unknown AuthnResult value");
        }

        if (!success) {
          logger.info(decorator.apply("Failed to authenticate user " + endUser));
          return;
        }
      }

      response.setHeader("GSA_APP_ID", state.getPviCredentials().getUsername());
      logger.info(decorator.apply("Succeeded to authenticate user " + endUser));
      snapshot = userSession.getSnapshot();
      state = ExportedState.make(snapshot);
    } else {
      response.setHeader("GSA_APP_ID", state.getPviCredentials().getUsername());
    }

    String authnJsonString = state.toJsonString();
    logger.fine("authn info " + authnJsonString);

    response.setHeader("GSA_SESSION_ID",
        (userSession != null ? userSession.getSessionId() : session.getSessionId()));
    OutputStream output
        = initRawResponseWithHeaders(response, HttpServletResponse.SC_OK,
            HttpUtil.TYPE_OCTET_STREAM);
    try {
      output.write(authnJsonString.getBytes());
    } finally {
      output.close();
    }
  }
}
