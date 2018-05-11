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

package com.google.enterprise.secmgr.authncontroller;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.secmgr.authncontroller.AuthnSession.AuthnState;
import com.google.enterprise.secmgr.common.CookieStore;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.HttpUtil.FormParameterCodingException;
import com.google.enterprise.secmgr.common.IdentityUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.AuthnMechGroups;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.enterprise.secmgr.ulf.FormResponse;
import com.google.inject.Singleton;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.PrintWriter;
import java.net.URL;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.joda.time.DateTimeUtils;

/**
 * The authentication controller.
 */
@Singleton
@ThreadSafe
public class AuthnController {

  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());
  private static final Logger logger = Logger.getLogger(AuthnController.class.getName());
  private static final int DEFAULT_MAX_PROMPTS = 3;
  private static final String ULF_ERROR_MSG =
      "Login failed. Please check your username(s) and password(s).";

  @GuardedBy("this") private ImmutableSet<CredentialsGatherer> gatherers;
  @GuardedBy("this") private ImmutableSet<AuthnModule> modules;
  @GuardedBy("this") private int maxPrompts;
  @GuardedBy("this") private AuthnState forceAuthnState;
  @GuardedBy("this") private boolean isSecureSearchApiMode = false;

  @Inject
  private AuthnController() {
    gatherers = ImmutableSet.of();
    modules = ImmutableSet.of();
    reset();
  }

  private synchronized ImmutableSet<CredentialsGatherer> getCredentialsGatherers() {
    return gatherers;
  }

  public synchronized void setCredentialsGatherers(Set<CredentialsGatherer> gatherers) {
    this.gatherers = ImmutableSet.copyOf(gatherers);
  }

  private synchronized ImmutableSet<AuthnModule> getModules() {
    return modules;
  }

  public synchronized void setModules(Iterable<AuthnModule> modules) {
    this.modules = ImmutableSet.copyOf(modules);
  }

  /**
   * Gets the mode of secure search api or not.
   */
  public synchronized boolean isSecureSearchApiMode() {
    return isSecureSearchApiMode;
  }

  /**
   * Sets the mode for secure search api.
   * @param mode true if in secure search api mode.
   */
  public synchronized void setSecureSearchApiMode(boolean mode) {
    isSecureSearchApiMode = mode;
  }

  @VisibleForTesting
  public void reset() {
    setMaxPrompts(DEFAULT_MAX_PROMPTS);
    setForceAuthnState(null);
  }

  @VisibleForTesting
  public synchronized void setForceAuthnState(AuthnState state) {
    forceAuthnState = state;
  }

  /**
   * Get the prompt limit.
   *
   * This is the number of times the back end will prompt the user before giving up.
   *
   * @return The prompt limit.
   */
  public synchronized int getMaxPrompts() {
    return maxPrompts;
  }

  /**
   * Set the prompt limit.
   *
   * This is the number of times the back end will prompt the user before giving up.
   *
   * @param maxPrompts The new prompt limit.
   */
  public synchronized void setMaxPrompts(int maxPrompts) {
    this.maxPrompts = maxPrompts;
  }

  // **** Authentication: entry point and main dispatch. ****

  // All authentication requests enter here, including messages that are
  // returning from credentials gathering.  The caller is expected to have
  // checked that the incoming message is appropriate for the session's state.

  /**
   * Perform the authentication process for the security manager.
   *
   * This method may be called more than once before authentication is finished, so it
   * uses the session state to decide what needs to be done.
   *
   * @param session The current authentication session.
   * @param request The current HTTP request.
   * @param response The HTTP response to fill in before returning.
   * @return The result of authentication.
   * @throws IOException
   */
  public AuthnResult authenticate(AuthnSession session, HttpServletRequest request,
      HttpServletResponse response)
      throws IOException {
    logger.info(session.logMessage(
        "Entering authentication controller in state " + session.getState()));
    if (request != null) {
      session.updateIncomingCookies(request);
    }

    AuthnResult result;
    switch (maybeForceAuthnState(session)) {
      case IDLE:
        throw new IllegalStateException("IDLE state not allowed");
      case AUTHENTICATING:
        result = authenticateHandleAuthenticatingState(session, request, response);
        break;
      case IN_UL_FORM:
        result = authenticateHandleInUlfState(session, request, response);
        break;
      case IN_CREDENTIALS_GATHERER:
        result = authenticateHandleInCredentialsGathererState(session, request, response);
        break;
      default:
        throw new IllegalStateException("Unknown authentication state");
    }
    // Always update outgoing cookies on return.  Not necessary for UNFINISHED
    // because handlers returning that value do the update themselves.
    if (result != AuthnResult.UNFINISHED) {
      updateOutgoingCookies(session, response);
    }
    logger.info(session.logMessage(
        "Leaving authentication controller in state " + session.getState() +
        " with result " + result));
    return result;
  }

  private AuthnState maybeForceAuthnState(AuthnSession session) {
    AuthnState state = session.getState();
    synchronized (this) {
      if (forceAuthnState != null) {
        logger.info(session.logMessage(
            "Forcing authn dispatch from " + state + " to " + forceAuthnState));
        state = forceAuthnState;
        forceAuthnState = null;
      }
    }
    return state;
  }

  private AuthnResult authenticateHandleAuthenticatingState(
      AuthnSession session, HttpServletRequest request, HttpServletResponse response)
      throws IOException {

    // New request, so remove now-expired verifications.
    expireRequestVerifications(session);

    gsaLogger.log(session.getRequestId(),
        "Attempting to authenticate using pre-existing credentials.");
    boolean gathered = false;
    if (isSecureSearchApiMode() && request != null) {
      logger.fine("Gathered credentials through initial http request");
      gathered = true;
    }

    if (verifyCredentials(session, request, gathered)) {
      return AuthnResult.SUCCESSFUL;
    }

    gsaLogger.log(session.getRequestId(),
        "Unable to authenticate with pre-existing credentials. "
            + "Starting credentials gathering.");

    return startGatheringCredentials(session, request, response);
  }

  private AuthnResult authenticateHandleInCredentialsGathererState(
      AuthnSession session, HttpServletRequest request, HttpServletResponse response)
      throws IOException {

    // Get the current credentials-gatherer element.
    CredentialsGathererElement element = session.getCredentialsGathererElement();
    SessionView view = element.getSessionView();

    // Update the element's view with the new set of user-agent cookies.
    view = view.withNewUserAgentCookies(session.getUserAgentCookies());
    element = element.newSessionView(view);
    updateAuthorityCookies(session, element);
    session.setCredentialsGathererElement(element);

    // Log the return.
    CredentialsGatherer gatherer = element.getGatherer();
    logger.info(view.logMessage("Returning to credentials gatherer: %s",
            gatherer.getClass().getSimpleName()));
    logCredentialsGathererCookies("after", element);

    // Check if we need to continue this credential gatherer.
    updateOutgoingCookies(session, response);
    if (gatherer.continueGathering(element, request, response)) {
      logger.info(view.logMessage("Credentials gatherer not finished: %s",
              gatherer.getClass().getSimpleName()));
      logCredentialsGathererCookies("before", element);
      return AuthnResult.UNFINISHED;
    }

    element.updateSessionState(session);

    // We're done running the credentials gatherer on this mechanism.
    logger.info(view.logMessage("Done gathering: %s on %s",
            gatherer.getClass().getSimpleName(),
            view.getMechanism().getName()));

    return tryNextCredentialsGatherer(session, request, response);
  }

  private AuthnResult authenticateHandleInUlfState(
      AuthnSession session, HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    if (isSecureSearchApiMode) {
      return AuthnResult.UNFINISHED;
    }

    // Update the session state with the form submission.
    logger.info(session.logMessage("Processing Universal Login Form submission."));
    ImmutableList<FormResponse> formResponses;
    try {
      formResponses = session.getUniversalLoginForm()
          .handleFormSubmit(request, session.getSessionId());
    } catch (FormParameterCodingException e) {
      // This was a parsing error, which indicates a problem with the incoming
      // POST.  Perhaps it's a transient problem, so re-post the form and try
      // again.
      String message =
          "Error while processing Universal Login Form submission: " + e.getMessage();
      logger.warning(session.logMessage(message));
      renderUniversalLoginForm(session, request, response, message);
      return AuthnResult.UNFINISHED;
    }
    session.updateSessionState(
        convertFormResponses(formResponses, session.getSnapshot().getConfig()));

    // Done with ULF for now.
    session.returnToAuthenticatingState();

    return maybeRetryGatheringCredentials(session, request, response);
  }

  private AuthnSessionState convertFormResponses(Iterable<FormResponse> responses,
      SecurityManagerConfig config) {
    AuthnSessionState delta = AuthnSessionState.empty();
    for (FormResponse response : responses) {
      if (response.getElement().isActive()) {
        List<Credential> credentials = Lists.newArrayList();
        if (response.getUsername() != null) {
          String[] parsed = IdentityUtil.parseNameAndDomain(response.getUsername());
          credentials.add(AuthnPrincipal.make(parsed[0], 
              config.getCredentialGroup(response.getElement().getName()).getName(), parsed[1]));
        }
        if (response.getPassword() != null) {
          credentials.add(CredPassword.make(response.getPassword()));
        }
        if (!credentials.isEmpty()) {
          delta = delta.addCredentials(
              config.getCredentialGroup(response.getElement().getName()).getAuthority(),
              credentials);
        }
      }
    }
    return delta;
  }

  // **** The core credentials-gathering loop. ****

  // It's only a logical "loop", because it can send messages to the user in the
  // middle of the loop and then branch back into the loop when the user
  // responds.  Our position in the "loop" is maintained in the session state.

  private AuthnResult startGatheringCredentials(AuthnSession session, HttpServletRequest request,
      HttpServletResponse response)
      throws IOException {
    session.setStateInCredentialsGatherer(getCredentialsGatherers());
    return tryNextCredentialsGatherer(session, request, response);
  }

  private AuthnResult tryNextCredentialsGatherer(AuthnSession session, HttpServletRequest request,
      HttpServletResponse response)
      throws IOException {

    // See if there's a credentials gatherer to try.
    SessionSnapshot snapshot = session.getSnapshot();
    while (true) {
      AuthnSession.ClientPair clientPair = session.getNextClientPair();
      if (clientPair == null) {
        break;
      }
      CredentialsGatherer gatherer = clientPair.getCredentialsGatherer();
      AuthnMechanism mechanism = clientPair.getMechanism();
      SessionView view = snapshot.getView(mechanism);
      if (gatherer.willHandle(view)) {
        CredentialsGathererElement element = new CredentialsGathererElementImpl(gatherer, view);
        logger.info(view.logMessage("Start gathering: %s on %s",
                gatherer.getClass().getSimpleName(),
                mechanism.getName()));
        session.setCredentialsGathererElement(element);
        updateOutgoingCookies(session, response);
        if (gatherer.startGathering(element, request, response)) {
          logCredentialsGathererCookies("before", element);
          return AuthnResult.UNFINISHED;
        }
        element.updateSessionState(session);
        snapshot = session.getSnapshot();
      }
    }

    // Done with credentials gatherers.
    session.returnToAuthenticatingState();

    // Consider trying the ULF.
    if (shouldTryUniversalLoginForm(session)) {
      session.setStateInUniversalLoginForm();
      renderUniversalLoginForm(session, request, response, null);
      return AuthnResult.UNFINISHED;
    } else {
      logger.info(session.logMessage(
          "Not trying Universal Login Form because no remaining credential group can use it."));
      gsaLogger.log(session.getRequestId(),
          "Not trying Universal Login Form because no remaining credential group can use it.");
    }

    // Otherwise consider starting over.
    return maybeRetryGatheringCredentials(session, request, response);
  }

  // Called when we have tried all the credentials-gathering mechanisms without
  // success.
  private AuthnResult maybeRetryGatheringCredentials(AuthnSession session,
      HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    // See if we're done.
    if (verifyCredentials(session, request, true)) {
      logger.info(session.logMessage("Credentials verified."));
      return AuthnResult.SUCCESSFUL;
    }

    // Otherwise consider starting over.
    logger.info(session.logMessage("Credentials verification failed."));

    // If we haven't exceeded the limit, re-try the credentials gathering.
    if (session.incrementPromptCounter() < getMaxPrompts()) {
      logger.info(session.logMessage("Re-trying credential gathering stage."));
      return startGatheringCredentials(session, request, response);
    }

    // Otherwise, all we can do is fail.
    logger.info(session.logMessage(
        "Exceeded credential gathering retry limit; returning authentication failure."));
    return AuthnResult.UNSUCCESSFUL;
  }

  // **** Helper methods for credentials gathering. ****

  private void expireRequestVerifications(AuthnSession session) {
    AuthnSessionState state = AuthnSessionState.empty();
    for (Map.Entry<AuthnAuthority, Verification> entry
             : getAllVerifications(session, session.getSessionState())) {
      Verification verification = entry.getValue();
      if (verification.getExpirationTime() == Verification.EXPIRES_AFTER_REQUEST) {
        state = state.removeVerification(entry.getKey(), verification);
      }
    }
    session.updateSessionState(state);
  }

  private Iterable<Map.Entry<AuthnAuthority, Verification>> getAllVerifications(
      AuthnSession session, AuthnSessionState state) {
    return state.computeSummary(session.getCredentialGroups()).getVerificationsMap().entrySet();
  }

  private boolean verifyCredentials(AuthnSession session,
                                    HttpServletRequest request,
                                    boolean haveRunCredentialsGatherers) {
    runMechanisms(session, request);
    return session.getSnapshot().getView().isSatisfied(haveRunCredentialsGatherers);
  }

  private void runMechanisms(AuthnSession session, HttpServletRequest request) {
    SessionSnapshot snapshot = session.getSnapshot();
    List<AuthnMechanism> toTry = Lists.newArrayList(snapshot.getConfig().getMechanisms());
    List<AuthnMechanism> groupsMechs = getGroupsMechsFromRunnableMechanisms(toTry);
    while (!toTry.isEmpty()) {
      List<AuthnMechanism> runnable = getRunnableMechanisms(toTry, snapshot, request);
      // Don't continue iterating if we couldn't find any runnable mechanisms.
      if (runnable.isEmpty()) {
        break;
      }
      for (AuthnMechanism mechanism : runnable) {
        SessionView view = snapshot.getView(mechanism);
        invokeModule(getModule(view), view, session);
        // Update the snapshot to reflect any changes made by the module.
        snapshot = session.getSnapshot();
      }
    }

    while (!groupsMechs.isEmpty()) {
      List<AuthnMechanism> runnable = getRunnableMechanisms(groupsMechs, snapshot, request);
      // Don't continue iterating if we couldn't find any runnable mechanisms.
      if (runnable.isEmpty()) {
        break;
      }
      for (AuthnMechanism groupsMech : runnable) {
        SessionView view = snapshot.getView(groupsMech);
        invokeModule(getModule(view), view, session);
        // Update the snapshot to reflect any changes made by the module.
        snapshot = session.getSnapshot();
      }
    }
  }

  private List<AuthnMechanism> getGroupsMechsFromRunnableMechanisms(
      List<AuthnMechanism> mechanisms) {
    List<AuthnMechanism> groupsMechs = Lists.newArrayList();
    int size = mechanisms.size();
    for (int i = 0; i < size; ++i) {
      AuthnMechanism mechanism = mechanisms.get(i);
      if (AuthnMechGroups.class.isInstance(mechanism)) {
        mechanisms.remove(mechanism);
        groupsMechs.add(mechanism);
      }
      size = mechanisms.size();
    }
    return groupsMechs;
  }


  private List<AuthnMechanism> getRunnableMechanisms(List<AuthnMechanism> mechanisms,
      SessionSnapshot snapshot, HttpServletRequest request) {
    List<AuthnMechanism> runnable = Lists.newArrayList();
    Iterator<AuthnMechanism> iter = mechanisms.iterator();
    while (iter.hasNext()) {
      AuthnMechanism mechanism = iter.next();
      SessionView view = snapshot.getView(mechanism);
      AuthnModule module = getModule(view);
      // Skip if no module will handle this view.
      if (module == null) {
        iter.remove();
        continue;
      }
      // Skip (for now) if this id has an unexpired verification.
      if (!view.isIndeterminate()) {
        continue;
      }
      Runnability runnability = Runnability.analyzeAuthority(view, request);
      Runnability.Status status = runnability.getStatus();
      logger.info(view.logMessage("Mechanism has runnability status %s: %s, has request %s",
              status, mechanism.getName(),
              (request == null ? "no" : "yes")));
      switch (status) {
        case READY:
          iter.remove();  // Don't try same ID more than once.
          runnable.add(mechanism);
          break;
        case NOT_READY:
          break;
        case SATISFIED:
          iter.remove();
          break;
        default:
          throw new IllegalStateException("Unknown Runnability.Status: " + status);
      }
    }
    return runnable;
  }

  private AuthnModule getModule(SessionView view) {
    for (AuthnModule module : getModules()) {
      if (module.willHandle(view)) {
        return module;
      }
    }
    return null;
  }

  @VisibleForTesting
  public static VerificationStatus invokeModule(AuthnModule module, SessionView view,
      AuthnSession session) {
    if (module == null) {
      logger.warning("No module");
      return VerificationStatus.INDETERMINATE;
    }

    AuthnSessionState state;
    try {
      state = module.authenticate(view);
    } catch (InterruptedIOException e) {
      logger.warning(session.logMessage("Authentication module timed out: " + e.getMessage()));
      gsaLogger.log(view.getRequestId(), "Authentication module timed out: " + e.getMessage());
      return VerificationStatus.INDETERMINATE;
    } catch (IOException e) {
      logger.log(Level.WARNING, session.logMessage("Error in authentication module: "), e);
      gsaLogger.log(view.getRequestId(), "Error in authentication module: " + e.getMessage());
      return VerificationStatus.INDETERMINATE;
    } catch (AuthnModuleException e) {
      logger.info(session.logMessage(
          "Authentication module indeterminate: " + e.getMessage()));
      gsaLogger.log(view.getRequestId(),
          "Authentication module indeterminate: " + e.getMessage());
      return VerificationStatus.INDETERMINATE;
    }
    String mechName = view.getMechanism().getName();
    Set<Verification> verifications
        = state.computeSummary(session.getCredentialGroups())
        .getVerifications(view.getCredentialFilter(), DateTimeUtils.currentTimeMillis());
    VerificationStatus status = Verification.getStatus(verifications);
    switch (status) {
      case VERIFIED:
        logger.info(view.logMessage("Credentials verified: %s", mechName));
        gsaLogger.log(view.getRequestId(), "The credentials were verified by " + mechName);
        break;
      case REFUTED:
        logger.info(view.logMessage("Credentials refuted: %s", mechName));
        gsaLogger.log(view.getRequestId(), "The credentials were refuted by " + mechName);
        break;
      case INDETERMINATE:
        logger.info(view.logMessage("Verification abandoned: %s", mechName));
        gsaLogger.log(view.getRequestId(),
            "The credentials could not be verified for " + mechName);
        break;
      default:
        throw new IllegalStateException("Unknown verification status: " + status);
    }
    session.updateSessionState(state);
    return status;
  }

  /**
   * Tests that a given expression is true, and throws an exception otherwise.
   * This exits the module cleanly with an INDETERMINATE result, logging a
   * descriptive message generated from a given format string and arguments.
   *
   * @param isValid The boolean value of the expression.
   * @param format The format string used to generate the exception message.
   * @param args The arguments used to generate the exception message.
   */
  public static void check(boolean isValid, String format, Object... args)
      throws AuthnModuleException {
    if (!isValid) {
      throw new AuthnModuleException(String.format(format, args));
    }
  }

  private boolean shouldTryUniversalLoginForm(AuthnSession session) {
    SessionSnapshot snapshot = session.getSnapshot();
    for (CredentialGroup group : snapshot.getConfig().getCredentialGroups()) {
      if (group.canUseUlfCredentials() && !snapshot.getView(group).isSatisfied(true)) {
        return true;
      }
    }
    return false;
  }

  private void renderUniversalLoginForm(AuthnSession session, HttpServletRequest request,
      HttpServletResponse response, @Nullable String errorMessage)
      throws IOException {
    if (isSecureSearchApiMode()) {
      return;
    }

    logger.info(session.logMessage("Rendering Universal Login Form."));
    gsaLogger.log(session.getRequestId(), "Rendering Universal Login Form.");
    if (null == SessionUtil.findGsaSessionId(request)) {
      addAuthnSessionCookie(session, response);
    }
    updateOutgoingCookies(session, response);
    PrintWriter writer = ServletBase.initNormalResponse(response);
    writer.print(session.getUniversalLoginForm()
        .generateForm((errorMessage == null && session.getPromptCounter() > 0)
            ? ULF_ERROR_MSG
            : errorMessage));
    writer.close();
  }

  private void addAuthnSessionCookie(AuthnSession session, HttpServletResponse response) {
    SessionView view = session.getSnapshot().getView();
    CookieStore outgoingCookies = GCookie.makeStore();
    GCookie.Builder builder = GCookie.builder(SessionUtil.GSA_SESSION_ID_COOKIE_NAME)
        .setValue(session.getSessionId()).setPath("/");
    outgoingCookies.add(builder.build());
    logger.info(view.logMessage("%s",
        GCookie.responseCookiesMessage("Secmgr cookies to user agent", outgoingCookies)));
    gsaLogger.log(session.getRequestId(),
        GCookie.responseCookiesMessage("Secmgr cookies to user agent", outgoingCookies));
    GCookie.addHttpResponseCookies(outgoingCookies, response);
  }

  // Update the cookies going to the user agent.  This *must* be done prior to
  // writing the body of the response.
  private void updateOutgoingCookies(AuthnSession session, HttpServletResponse response) {
    SessionView view = session.getSnapshot().getView();
    // The url can be /samlauthn or /authenticate.
    URL url = view.getAuthnEntryUrl();
    if (url == null) {
      return;
    }
    CookieStore outgoingCookies = GCookie.makeStore();
    for (GCookie cookie : view.getAuthorityCookies()) {
      if (cookie.isGoodFor(HttpUtil.toUri(url))) {
        outgoingCookies.add(cookie);
      }
    }
    logger.info(view.logMessage("%s",
        GCookie.responseCookiesMessage("Outgoing cookies to user agent", outgoingCookies)));
    gsaLogger.log(session.getRequestId(),
        GCookie.responseCookiesMessage("Outgoing cookies to user agent", outgoingCookies));
    GCookie.addHttpResponseCookies(outgoingCookies, response);
  }

  // Used on return from credentials gatherer.  Removes authority cookies that
  // shadow incoming cookies, since the incoming cookies must be newer than the
  // previously gathered ones.
  private void updateAuthorityCookies(final AuthnSession session,
      CredentialsGathererElement element) {
    SessionView view = element.getSessionView();
    element.addSessionState(
        AuthnSessionState.empty()
        .removeCookies(view.getAuthority(),
            Iterables.filter(view.getAuthorityCookies(),
                new Predicate<GCookie>() {
                  @Override
                  public boolean apply(GCookie cookie) {
                    return session.hasUserAgentCookie(cookie.getName());
                  }
                })));
  }

  private void logCredentialsGathererCookies(String when, CredentialsGathererElement element) {
    SessionView view = element.getSessionView();
    logger.info(view.logMessage("%s",
        GCookie.responseCookiesMessage("Authority cookies " + when + " credentials gatherer",
            view.getAuthorityCookies())));
  }

  private static final class CredentialsGathererElementImpl implements CredentialsGathererElement {
    @Nonnull final CredentialsGatherer gatherer;
    @Nonnull final SessionView view;
    @GuardedBy("this") @Nonnull AuthnSessionState sessionState;
    @GuardedBy("this") @Nullable Object privateState;

    CredentialsGathererElementImpl(CredentialsGatherer gatherer, SessionView view,
        AuthnSessionState sessionState, @Nullable Object privateState) {
      Preconditions.checkNotNull(gatherer);
      Preconditions.checkNotNull(view);
      Preconditions.checkNotNull(sessionState);
      this.gatherer = gatherer;
      this.view = view;
      this.sessionState = sessionState;
      this.privateState = privateState;
    }

    CredentialsGathererElementImpl(CredentialsGatherer gatherer, SessionView view) {
      this(gatherer, view, AuthnSessionState.empty(), null);
    }

    @Override
    public CredentialsGatherer getGatherer() {
      return gatherer;
    }

    @Override
    public SessionView getSessionView() {
      return view;
    }

    @Override
    public synchronized CredentialsGathererElement newSessionView(SessionView view) {
      return new CredentialsGathererElementImpl(gatherer, view, sessionState, privateState);
    }

    @Override
    public synchronized void addSessionState(AuthnSessionState delta) {
      this.sessionState = sessionState.add(delta);
    }

    @Override
    public void updateSessionState(AuthnSession session) {
      AuthnSessionState sessionState;
      synchronized (this) {
        sessionState = this.sessionState;
        this.sessionState = AuthnSessionState.empty();
      }
      session.updateSessionState(sessionState);
    }

    @Override
    public synchronized void setPrivateState(Object privateState) {
      this.privateState = privateState;
    }

    @Override
    public synchronized <T> T getPrivateState(Class<T> clazz) {
      return clazz.cast(privateState);
    }
  }
}
