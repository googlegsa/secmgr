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

import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAuthnFailureStatus;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeResponderFailureStatus;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeSecurityFailureStatus;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.runEncoder;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.saml.SamlSharedData;

import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.log.JdkLogChute;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPArtifactEncoder;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.security.SecurityException;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * An abstract base class for servlets participating in SAML SSO authentication.
 */
@Immutable
@ParametersAreNonnullByDefault
public abstract class SamlIdpServlet extends SamlServlet {
  private static final Logger logger = Logger.getLogger(SamlIdpServlet.class.getName());

  @Nullable private final String forcedResponseBinding;
  @Nonnull private final AuthnController controller;
  @Nonnull private final VelocityEngine velocityEngine;

  protected SamlIdpServlet(SamlSharedData sharedData) {
    this(sharedData, null);
  }

  @VisibleForTesting
  protected SamlIdpServlet(SamlSharedData sharedData, @Nullable String forcedResponseBinding) {
    super(sharedData);
    this.forcedResponseBinding = forcedResponseBinding;
    controller = ConfigSingleton.getInstance(AuthnController.class);
    velocityEngine = makeVelocityEngine();
  }

  private static VelocityEngine makeVelocityEngine() {
    VelocityEngine engine = new VelocityEngine();
    engine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS, JdkLogChute.class.getName());
    engine.setProperty(JdkLogChute.RUNTIME_LOG_JDK_LOGGER, SamlIdpServlet.class.getName());
    engine.setProperty(RuntimeConstants.FILE_RESOURCE_LOADER_PATH, FileUtil.getContextDirectory());
    try {
      engine.init();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    return engine;
  }

  /**
   * Gets the binding to use for sending a response.
   *
   * @param context A message context being used to send a response.
   * @return The binding to be used.
   */
  @Nullable
  public synchronized String getResponseBinding(SAMLMessageContext<?, ?, ?> context) {
    return (forcedResponseBinding != null)
        ? forcedResponseBinding
        : context.getPeerEntityEndpoint().getBinding();
  }

  /**
   * Enter the authentication controller from a SAML servlet.  Provides appropriate SAML
   * responses when needed.
   *
   * @param session The authentication session.
   * @param request Incoming HTTP request.
   * @param response HTTP response.
   * @throws IOException
   */
  protected void doAuthn(AuthnSession session, HttpServletRequest request,
      HttpServletResponse response)
      throws IOException {
    switch (controller.authenticate(session, request, response)) {
      case SUCCESSFUL:
        // Generate a successful SAML response.
        SAMLMessageContext<AuthnRequest, Response, NameID> context = session.getSamlSsoContext();
        encodeResponse(SessionUtil.getLogDecorator(session.getSessionId()), response, context,
            (new SimpleResponseGenerator(context)).generate(session.getSnapshot()));
        session.setStateIdle();
        break;

      case UNSUCCESSFUL:
        // Generate an unsuccessful SAML response.
        genericFailure(session, response, makeAuthnFailureStatus());
        break;

      case UNFINISHED:
        // The response was set up by the back end.
        break;

      default:
        throw new IllegalStateException("Unknown AuthnResult value");
    }
  }

  /**
   * Generates a suitable error response for when there's no session.
   *
   * @param request Incoming HTTP request.
   * @param response HTTP response.
   * @throws IOException
   */
  protected void failNoSession(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    initErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
  }

  /**
   * Generates a suitable error response for an exception.
   *
   * @param exception The exception that was caught.
   * @param session Current authentication session.
   * @param request Incoming HTTP request.
   * @param response HTTP response.
   * @throws IOException if there are I/O errors while generating the response.
   */
  protected void failFromException(Exception exception, AuthnSession session,
      HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    Status status;
    if (exception instanceof AuthnSession.InconsistentStateException) {
      status = makeResponderFailureStatus(exception.getMessage());
    } else if (exception instanceof SecurityException) {
      status = makeSecurityFailureStatus(exception.getMessage());
    } else {
      String message = "Internal error while authenticating: ";
      logger.log(Level.WARNING, session.logMessage(message), exception);
      status = makeResponderFailureStatus(message + exception.getMessage());
    }
    genericFailure(session, response, status);
  }

  private void genericFailure(AuthnSession session, HttpServletResponse response, Status status)
      throws IOException {
    Decorator decorator = SessionUtil.getLogDecorator(session.getSessionId());
    String message = (status.getStatusMessage() != null)
        ? Strings.emptyToNull(status.getStatusMessage().getMessage())
        : null;
    SAMLMessageContext<AuthnRequest, Response, NameID> context;
    try {
      context = session.getSamlSsoContext();
    } catch (IllegalStateException e) {
      logger.warning(decorator.apply(
          "Unable to send SAML response, sending empty response with redirection to '/' instead"
          + ((message != null) ? ": " + message : "")));
      sendRedirect(response, "/");
      session.setStateIdle();
      return;
    }
    if (message != null) {
      logger.warning(decorator.apply(message));
    }
    encodeResponse(decorator, response, context,
        (new FailureResponseGenerator(context, status)).generate(null));
    session.setStateIdle();
  }

  /**
   * Generates a suitable error response for an exception with http post binding.
   *
   * @param exception The exception that was caught.
   * @param session Current authentication session.
   * @param request Incoming HTTP request.
   * @param response HTTP response.
   * @throws IOException if there are I/O errors while generating the response.
   */
  protected void failFromRuntimeExceptionWithPostBinding(Exception exception,
      AuthnSession session, HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    Status status;
    String externalMessage;
    if (exception instanceof AuthnSession.InconsistentStateException) {
      String message = "Authn session state is inconsistant: ";
      logger.log(Level.WARNING, session.logMessage(message), exception);
      status = makeResponderFailureStatus(message + exception.getMessage());
      externalMessage =
          "<html><body><H1>Error 500: No authenticated session found.</H1>\n" +
          "If you encountered this page by hitting the Back button, you are " +
          "leaving an authenticated session.  You may need to navigate back " +
          "to the page you submitted your search request from and login again " +
          "in order to perform a search over secure content. Please be advised " +
          "that we recommend navigating the page by using links on the page " +
          "itself instead of the Back button on the browser as this will avoid " +
          "this error in the future.</body></html>";
    } else {
      String message = "Internal error while authenticating: ";
      logger.log(Level.WARNING, session.logMessage(message), exception);
      status = makeResponderFailureStatus(message + exception.getMessage());
      externalMessage =
          "<html><body><H1>Error 500: Internal Error.</H1>\n" +
          "Internal error encountered while authenticating " +
          exception.getMessage() +
          "</body></html>";
    } 
    postBindingFailure(session, externalMessage, response, status);
  }
 
  private void postBindingFailure(AuthnSession session, String externalMessage,
      HttpServletResponse response, Status status)
      throws IOException {
    Decorator decorator = SessionUtil.getLogDecorator(session.getSessionId());
    String message = (status.getStatusMessage() != null)
        ? Strings.emptyToNull(status.getStatusMessage().getMessage())
        : null;
    SAMLMessageContext<AuthnRequest, Response, NameID> context;
    try {
      context = session.getSamlSsoContext();
    } catch (IllegalStateException e) {
      logger.warning(decorator.apply(
          "Unable to send SAML response, sending error instead" +
          ((message != null) ? ": " + message : "")));
      PrintWriter writer
          = ServletBase.initNormalResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
      writer.write(externalMessage);
      writer.close();
      session.setStateIdle();
      return;
    }
    if (message != null) {
      logger.warning(decorator.apply(message));
    }
    encodeResponse(decorator, response, context,
        (new FailureResponseGenerator(context, status)).generate(null));
    session.setStateIdle(); 
  }

  @VisibleForTesting
  protected void encodeResponse(
      Decorator decorator,
      HttpServletResponse response,
      SAMLMessageContext<AuthnRequest, Response, NameID> context,
      Response samlResponse)
      throws IOException {
    context.setOutboundSAMLMessage(samlResponse);

    // Encode the response message.
    initResponse(response);
    context.setOutboundMessageTransport(new HttpServletResponseAdapter(response, true));

    String responseBinding = getResponseBinding(context);
    if (SAMLConstants.SAML2_ARTIFACT_BINDING_URI.equals(responseBinding)) {
      HTTPArtifactEncoder encoder = new HTTPArtifactEncoder(null, null, getArtifactMap());
      encoder.setPostEncoding(false);
      runEncoder(encoder, context, decorator);
    } else if (SAMLConstants.SAML2_POST_BINDING_URI.equals(responseBinding)) {
      HTTPPostEncoder encoder = new HTTPPostEncoder(velocityEngine, "saml-post-template.xhtml");
      // Synchronize access to velocity engine; I don't trust it to be thread-safe.
      synchronized (velocityEngine) {
        runEncoder(encoder, context, decorator);
      }
    } else {
      throw new IllegalStateException("Unknown binding: " + responseBinding);
    }
  }
}
