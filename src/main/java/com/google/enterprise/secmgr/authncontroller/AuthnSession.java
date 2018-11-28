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

package com.google.enterprise.secmgr.authncontroller;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableCollection;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.enterprise.frontend.AuthNConstants;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.secmgr.common.CookieStore;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.IdentityUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.ulf.FormElement;
import com.google.enterprise.secmgr.ulf.UniversalLoginForm;
import com.google.enterprise.secmgr.ulf.UniversalLoginFormHtml;
import com.google.enterprise.sessionmanager.SessionManagerInterfaceBase;

import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.ArrayDeque;
import java.util.Queue;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;

import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 * An object to represent the session information for authentication.
 */
@ThreadSafe
public class AuthnSession implements Serializable {

  // fields that are required for serializing/restoring SamlContext
  private String samlRequest;
  private String relayState;
  private String serverName;
  private int serverPort;
  private String scheme;
  private String requestURI;


  public static final String AUTHN_SESSION = "AuthnSession";

  private static final Logger logger = Logger.getLogger(AuthnSession.class.getName());
  private static final LogClient GSA_LOGGER = new LogClient("Security Manager");

  @Inject private static AuthnSessionManager sessionManager;
  private static boolean secureSearchApiMode = false;

  private boolean hasModifications = false;

  public boolean hasModifications() {
    return hasModifications;
  }

  public void resetModifications() {
    this.hasModifications = false;
  }

  public String getSamlRequest() {
    return samlRequest;
  }

  public void setSamlRequest(String samlRequest) {
    this.samlRequest = samlRequest;
  }

  public String getRelayState() {
    return relayState;
  }

  public void setRelayState(String relayState) {
    this.relayState = relayState;
  }

  public void setServerName(String serverName) {
    this.serverName = serverName;
  }

  public void setServerPort(int serverPort) {
    this.serverPort = serverPort;
  }

  public void setScheme(String scheme) {
    this.scheme = scheme;
  }

  public void setRequestURI(String requestURI) {
    this.requestURI = requestURI;
  }

  public String getServerName() {
    return serverName;
  }

  public int getServerPort() {
    return serverPort;
  }

  public String getScheme() {
    return scheme;
  }

  public String getRequestURI() {
    return requestURI;
  }

  /**
   * The authentication controller is a state machine.  This is the set of
   * possible states for the controller.
   */
  public enum AuthnState {
    // No request is being processed.
    IDLE,
    // A request is being processed.
    AUTHENTICATING,
    // A ULF has been sent to the user agent and we're waiting for a reply.
    IN_UL_FORM,
    // a credentials gatherer is running and we're waiting for it to finish.
    IN_CREDENTIALS_GATHERER
  }

  /**
   * A combination of a credentials gatherer and an authentication mechanism.
   * The authentication controller loops over all possible combinations of these
   * to decide which credentials gatherers to try with which mechanisms.
   */
  @Immutable
  @ParametersAreNonnullByDefault
  public static final class ClientPair implements Serializable {
    @Nonnull private final CredentialsGatherer gatherer;
    @Nonnull private final AuthnMechanism mechanism;

    private ClientPair(CredentialsGatherer gatherer, AuthnMechanism mechanism) {
      Preconditions.checkNotNull(gatherer);
      Preconditions.checkNotNull(mechanism);
      this.gatherer = gatherer;
      this.mechanism = mechanism;
    }

    /**
     * Gets the credentials gatherer.
     */
    @Nonnull
    public CredentialsGatherer getCredentialsGatherer() {
      return gatherer;
    }

    /**
     * Gets the mechanism.
     */
    @Nonnull
    public AuthnMechanism getMechanism() {
      return mechanism;
    }
  }

  @GuardedBy("itself")
  private final CookieStore incomingCookies;
  private final String sessionId;

  private transient SecurityManagerConfig config;

  @GuardedBy("this")
  private AuthnState state;
  @GuardedBy("this")
  private transient HttpServletRequest request;
  @GuardedBy("this")
  private String requestId;
  @GuardedBy("this")
  private transient SAMLMessageContext<AuthnRequest, Response, NameID> samlSsoContext;
  @GuardedBy("this")
  private URL authnEntryUrl;
  @GuardedBy("this")
  private int promptCounter = 0;
  @GuardedBy("this")
  private UniversalLoginForm ulForm;
  @GuardedBy("this")
  private Queue<ClientPair> clientPairs;
  @GuardedBy("this")
  private CredentialsGathererElement clientElement;
  @GuardedBy("this")
  private AuthnState forceControllerFailure = null;
  @GuardedBy("this")
  private AuthnSessionState sessionState;

  public AuthnSession(SecurityManagerConfig config, String sessionId) {
    incomingCookies = GCookie.makeStore();
    this.sessionId = sessionId;
    this.requestId = null;
    this.config = config;
    sessionState = AuthnSessionState.empty();
    clientPairs = null;
    this.setStateIdle();
    logger.info(logMessage("created new session."));
  }

  @VisibleForTesting
  public static AuthnSession newInstance()
      throws IOException {
    return new AuthnSession(ConfigSingleton.getConfig(), SessionUtil.generateId());
  }

  @VisibleForTesting
  public static AuthnSession newInstance(String sessionId)
      throws IOException {
    return new AuthnSession(ConfigSingleton.getConfig(), sessionId);
  }

  @VisibleForTesting
  public static AuthnSession newInstance(SecurityManagerConfig config) {
    return new AuthnSession(config, SessionUtil.generateId());
  }

  /**
   * Sets secure search api mode.
   * @param mode true for secure search api mode
   */
  public static synchronized void setSecureSearchApiMode(boolean mode) {
    secureSearchApiMode = mode;
  }

  /**
   * Checks if it's in secure search api mode.
   * @return true if it's in secure search api mode.
   */
  public static synchronized boolean isSecureSearchApiMode() {
    return secureSearchApiMode;
  }


  public void addCredentials(String userId, String credentialGroup, String password) {
    String namespace = Strings.isNullOrEmpty(credentialGroup) ? CredentialGroup.DEFAULT_NAME
        : credentialGroup;
    String credPassword = (password == null) ? "" : password;
    String[] parsed = IdentityUtil.parseNameAndDomain(userId);
    AuthnPrincipal user = AuthnPrincipal.make(parsed[0],
        config.getCredentialGroup(namespace).getName(), parsed[1]);
    addCredentials(config.getCredentialGroup(namespace).getAuthority(), user,
        CredPassword.make(credPassword));
  }


  /**
   * Gets a snapshot of the session state.
   *
   * @return A snapshot object.
   */
  public SessionSnapshot getSnapshot() {
    String reqId;
    synchronized (this) {
      reqId = this.requestId;
    }
    return SessionSnapshot.make(sessionId, reqId, request, config, getAuthnEntryUrlInternal(),
        getUserAgentCookies(), getSessionState());
  }

  public SessionSnapshot getSnapshot(String requestId) {
    return SessionSnapshot.make(sessionId, requestId, request, config, getAuthnEntryUrlInternal(),
        getUserAgentCookies(), getSessionState());
  }

  private synchronized URL getAuthnEntryUrlInternal() {
    return authnEntryUrl;
  }

  @VisibleForTesting
  public synchronized SessionView getView(AuthnMechanism mechanism) {
    return getSnapshot().getView(mechanism);
  }

  // For use by AuthnController.
  synchronized AuthnSessionState getSessionState() {
    return sessionState;
  }

  void updateSessionState(final AuthnSessionState delta) {
    if (delta.isEmpty()) {
      return;
    }
    logger.info(logMessage("Modify session state:\n" + delta));
    synchronized (this) {
      hasModifications = true;
      sessionState = sessionState.add(delta);
    }
  }

  public void importSessionState(final AuthnSessionState delta) {
    logger.info(logMessage("Import session state:\n" + delta));
    synchronized (this) {
      sessionState = AuthnSessionState.empty().add(delta);
      hasModifications = true;
    }
  }

  @VisibleForTesting
  public ImmutableList<CredentialGroup> getCredentialGroups() {
    return config.getCredentialGroups();
  }

  @VisibleForTesting
  public ImmutableList<AuthnMechanism> getMechanisms() {
    return config.getMechanisms();
  }

  @VisibleForTesting
  public void addCookie(final AuthnAuthority authority, final GCookie cookie) {
    updateSessionState(AuthnSessionState.empty().addCookie(authority, cookie));
  }

  @VisibleForTesting
  public void addCredentials(final AuthnAuthority authority, final Credential... credentials) {
    updateSessionState(
        AuthnSessionState.empty().addCredentials(authority, Arrays.asList(credentials)));
  }

  @VisibleForTesting
  public void addCredentials(AuthnMechanism mechanism, Credential... credentials) {
    addCredentials(mechanism.getAuthority(), credentials);
  }

  @VisibleForTesting
  public void addVerification(AuthnAuthority authority, Verification verification) {
    updateSessionState(AuthnSessionState.empty()
        .addVerification(authority, verification));
  }

  @VisibleForTesting
  public ImmutableSet<Group> getVerifiedGroups() {
    return getSnapshot().getView().getVerifiedGroups();
  }

  /**
   * Gets the user-agent cookies for this session.
   *
   * @return An immutable copy of the cookies.
   */
  public ImmutableCollection<GCookie> getUserAgentCookies() {
    synchronized (incomingCookies) {
      incomingCookies.expireCookies();
      return ImmutableList.copyOf(incomingCookies);
    }
  }

  /**
   * Gets a named cookie from an incoming HTTP request.
   *
   * @param name The name of the cookie to return.
   * @return The corresponding cookie, or {@code null} if no such cookie.
   */
  public GCookie getUserAgentCookie(String name) {
    synchronized (incomingCookies) {
      incomingCookies.expireCookies();
      return incomingCookies.get(name);
    }
  }

  synchronized boolean hasUserAgentCookie(String name) {
    incomingCookies.expireCookies();
    return incomingCookies.contains(name);
  }

  /**
   * Collects cookies from an incoming request and updates our collection to
   * match.  Should be called by every servlet accepting requests from a user
   * agent.
   *
   * @param request The incoming request.
   */
  public void updateIncomingCookies(HttpServletRequest request) {
    CookieStore requestCookies
        = GCookie.parseHttpRequestCookies(request, SessionUtil.getLogDecorator(sessionId));
    logger.info(logMessage(
        GCookie.requestCookiesMessage("Incoming cookies from user agent", requestCookies)));
    GSA_LOGGER.info(requestId, GCookie.requestCookiesMessage(
        "Incoming cookies from user agent", requestCookies));
    synchronized (incomingCookies) {
      hasModifications = true;
      incomingCookies.clear();
      incomingCookies.addAll(requestCookies);
    }
  }

  /**
   * Gets the state of the authentication controller.
   *
   * @return The controller state, as an AuthnState instance.
   */
  public synchronized AuthnState getState() {
    return state;
  }

  /**
   * Indicates that we are not processing an authentication request.
   */
  public synchronized void setStateIdle() {
    setState(AuthnState.IDLE);
    samlSsoContext = null;
    authnEntryUrl = null;
    promptCounter = 0;
    ulForm = null;
    clearCredentialsGathererState();
    maybeFailForTest();
  }

  /**
   * Indicates that we are starting to process an authentication request.
   *
   * @param url The entry point URL.  Any query or fragment in the given URL
   *     will be discarded.
   * @param samlSsoContext The SAML message context object.  This is the context
   *     for the "server" side of the security manager, where we are acting as
   *     an IdP for the GSA.
   * @throws IOException if URL can't be parsed.
   */
  public synchronized void setStateAuthenticating(URL url,
      SAMLMessageContext<AuthnRequest, Response, NameID> samlSsoContext)
      throws IOException {
    Preconditions.checkNotNull(url);
    Preconditions.checkNotNull(samlSsoContext);
    setState(AuthnState.AUTHENTICATING, AuthnState.IDLE);
    // Discard any query or fragment parts.
    authnEntryUrl = new URL(url.getProtocol(), url.getHost(), url.getPort(), url.getPath());
    this.samlSsoContext = samlSsoContext;
    maybeFailForTest();
  }

  /**
   * Indicates that we are starting to process an authentication request from
   * EFE.
   *
   * @throws IOException if URL can't be parsed.
   */
  public synchronized void setStateAuthenticating()
      throws IOException {
    setState(AuthnState.AUTHENTICATING, AuthnState.IDLE);
    maybeFailForTest();
  }

  /**
   * Indicates that we are finished with a credentials gatherer or ULF.
   */
  public synchronized void returnToAuthenticatingState() {
    setState(AuthnState.AUTHENTICATING, AuthnState.IN_UL_FORM, AuthnState.IN_CREDENTIALS_GATHERER);
    ulForm = null;
    clearCredentialsGathererState();
    maybeFailForTest();
  }

  public synchronized void setRequest(HttpServletRequest request) {
    this.request = request;
  }

  public synchronized HttpServletRequest getRequest() {
    return request;
  }

  public synchronized void setRequestId(String requestId) {
    this.requestId = requestId;
  }

  public synchronized String getRequestId() {
    assertNotIdleState();
    return requestId;
  }

  /**
   * Gets the SAML message context for the session's current SSO exchange.  This
   * is the context for the "server" side of the security manager, where we are
   * acting as an IdP for the GSA.
   *
   * @return The message context object.
   * @throws InconsistentStateException if the current state is IDLE.
   */
  public synchronized SAMLMessageContext<AuthnRequest, Response, NameID> getSamlSsoContext() {
    assertNotIdleState();
    return samlSsoContext;
  }

  public synchronized void setSamlSsoContext(SAMLMessageContext<AuthnRequest, Response, NameID> context) {
    this.samlSsoContext = context;
  }

  /**
   * Gets the number of times the user has been prompted by the ULF.
   *
   * @return The number of prompts.
   * @throws InconsistentStateException if the current state is IDLE.
   */
  public synchronized int getPromptCounter() {
    assertNotIdleState();
    return promptCounter;
  }

  /**
   * Gets the number of times the user has been prompted by the ULF.  Meant to
   * be called immediately after one such prompt, it increments the counter as
   * well.
   *
   * @return The number of prompts.
   * @throws InconsistentStateException if controller state isn't AUTHENTICATING.
   */
  public synchronized int incrementPromptCounter() {
    assertState(AuthnState.AUTHENTICATING);
    return ++promptCounter;
  }

  /**
   * Gets the URL of the authentication entry point.  The returned URL will not
   * have a query or fragment part.
   *
   * @return The entry point URL.
   * @throws InconsistentStateException if the current state is IDLE.
   */
  public synchronized URL getAuthnEntryUrl() {
    assertNotIdleState();
    return authnEntryUrl;
  }

  /**
   * Gets the URL of the authentication entry point.  The returned URL will not
   * have a query or fragment part.
   *
   * @return The entry point URL as a string.
   */
  public String getAuthnEntryUrlString() {
    return getAuthnEntryUrl().toString();
  }

  /**
   * Indicates that we are sending a ULF to the user agent.  We will wait for a
   * POST from the user agent and process it when it arrives.
   *
   * @throws IllegalStateException if this is an illegal state transition.
   */
  public synchronized void setStateInUniversalLoginForm() throws IOException {
    setState(AuthnState.IN_UL_FORM, AuthnState.AUTHENTICATING);
    ulForm = getUlf();
    maybeFailForTest();
  }

  private UniversalLoginForm getUlf()
      throws IOException {
    SessionSnapshot snapshot = getSnapshot();
    ImmutableList.Builder<FormElement> builder = ImmutableList.builder();
    for (CredentialGroup credentialGroup : config.getCredentialGroups()) {
      if (!credentialGroup.canUseUlfCredentials()) {
        continue;
      }
      SessionView view = snapshot.getView(credentialGroup);
      builder.add(
          new FormElement(
              credentialGroup.getName(),
              credentialGroup.getDisplayName(),
              !view.isSatisfied(true),
              !view.hasVerifiedPrincipalAndPassword(),
              view.getUsername()));
    }
    URL url = snapshot.getAuthnEntryUrl();
    if (url == null) {
      return null;
    }
    return UniversalLoginForm.make(builder.build(),
        new UniversalLoginFormHtml(url.toString(), url.getHost()));
  }

  /**
   * Gets the session's ULF object.
   *
   * @return The ULF object.
   * @throws InconsistentStateException if controller state isn't IN_UL_FORM.
   */
  public synchronized UniversalLoginForm getUniversalLoginForm() {
    assertState(AuthnState.IN_UL_FORM);
    return ulForm;
  }

  /**
   * Indicates that we are passing control to one or more credentials gatherers.
   * The credentials gatherers will handle communications with the user agent
   * until they have finished.
   *
   * @param credentialsGatherers The credentials gatherers to try.
   * @throws IllegalStateException if this is an illegal state transition.
   */
  public synchronized void setStateInCredentialsGatherer(
      Iterable<CredentialsGatherer> credentialsGatherers) {
    Preconditions.checkNotNull(credentialsGatherers);
    setState(AuthnState.IN_CREDENTIALS_GATHERER, AuthnState.AUTHENTICATING);
    ImmutableList.Builder<ClientPair> builder = ImmutableList.builder();
    this.clientPairs = new ArrayDeque<>();
    for (CredentialsGatherer client : credentialsGatherers) {
      for (AuthnMechanism mechanism : config.getMechanisms()) {
        ClientPair clientPair = new ClientPair(client, mechanism);
        builder.add(clientPair);
        clientPairs.add(clientPair);
      }
    }
  }

  private synchronized void clearCredentialsGathererState() {
    clientPairs = null;
    clientElement = null;
  }

  /**
   * Sets the current credentials-gatherer element.  This method is intended for
   * use by the authentication controller.
   *
   * @param element The credentials-gatherer element to set.
   * @throws InconsistentStateException if not in CREDENTIALS_GATHERER state.
   */
  synchronized void setCredentialsGathererElement(CredentialsGathererElement element) {
    assertState(AuthnState.IN_CREDENTIALS_GATHERER);
    Preconditions.checkNotNull(element);
    this.clientElement = element;
  }

  /**
   * Gets the current credentials-gatherer element, assuming its gatherer has a
   * given class.  This method is intended for use by credentials gatherers.
   *
   * @param clazz The expected class of the credentials gatherer.
   * @return The current credentials-gatherer element.
   * @throws InconsistentStateException if not in CREDENTIALS_GATHERER state.
   * @throws IllegalStateException if gatherer has the wrong class.
   */
  public synchronized CredentialsGathererElement getCredentialsGathererElement(
      Class<? extends CredentialsGatherer> clazz) {
    assertState(AuthnState.IN_CREDENTIALS_GATHERER);
    CredentialsGatherer gatherer = clientElement.getGatherer();
    if (!clazz.isInstance(gatherer)) {
      throw new IllegalStateException("Incorrect credentials gatherer: " +
          gatherer.getClass().getName() + " expected: " + clazz.getName());
    }
    return clientElement;
  }

  /**
   * Gets the current credentials-gatherer element, regardless of its class.
   * This method is intended for use by the authentication controller.
   *
   * @return The current credentials-gatherer element.
   * @throws InconsistentStateException if not in CREDENTIALS_GATHERER state.
   */
  synchronized CredentialsGathererElement getCredentialsGathererElement() {
    assertState(AuthnState.IN_CREDENTIALS_GATHERER);
    return clientElement;
  }

  /**
   * Gets the next client pair, if any.  This method is intended for use by the
   * authentication controller.
   *
   * @return The next client pair, or {@code null} if none are left.
   * @throws InconsistentStateException if not in CREDENTIALS_GATHERER state.
   */
  synchronized ClientPair getNextClientPair() {
    assertState(AuthnState.IN_CREDENTIALS_GATHERER);
    if (clientPairs.isEmpty()) {
      return null;
    }
    ClientPair clientPair = clientPairs.remove();
    maybeFailForTest();
    return clientPair;
  }

  /**
   * @return The session ID string for this session.
   */
  public String getSessionId() {
    return sessionId;
  }

  /**
   * Transites from a state in expectedStates to targetState.
   * If there is no expectedStates, will set to targetState.
   * If the current state is not one of the expectedStates, throw an illegalStateTransition.
   * @param targetState The state to be change to.
   * @param expectedStates The states that the current state is expected to be.
   */
  @GuardedBy("this")
  private void setState(AuthnState targetState, AuthnState... expectedStates) {
    if (expectedStates.length == 0) {
      setStateInternal(targetState);
      return;
    }
    for (AuthnState expectedState : expectedStates) {
      if (state == expectedState) {
        setStateInternal(targetState);
        return;
      }
    }
    illegalStateTransition(targetState);
  }

  @GuardedBy("this")
  private void setStateInternal(AuthnState targetState) {
    // Don't log anything for non-change.
    if (state == targetState) {
      return;
    }
    // Don't log initial call to setState from session constructor.
    if (!(state == null && targetState == AuthnState.IDLE)) {
      logger.info(logMessage("State transition from " + state + " to " + targetState));
    }
    state = targetState;
    hasModifications = true;
  }

  private void illegalStateTransition(AuthnState targetState) {
    throw new IllegalStateException(
        "Illegal authentication state transition from " + state + " to " + targetState);
  }

  /**
   * Guarantees that the session's state matches one of the given states.
   *
   * @param expectedStates The expected states.
   * @return The actual state if it's one of the expected ones.
   * @throws InconsistentStateException if the current state doesn't match.
   */
  public synchronized AuthnState assertState(AuthnState... expectedStates) {
    for (AuthnState expectedState : expectedStates) {
      if (state == expectedState) {
        return state;
      }
    }
    throw makeInconsistentStateException(state, expectedStates);
  }

  @GuardedBy("this")
  private void assertNotIdleState() {
    if (state == AuthnState.IDLE) {
      throw makeInconsistentStateException(state);
    }
  }

  /**
   * Called when state is discovered to be inconsistent.
   */
  public InconsistentStateException makeInconsistentStateException(AuthnState state,
      AuthnState... expectedStates) {
    return new InconsistentStateException(state, expectedStates);
  }

  /**
   * The exception thrown by the session when it detects that a session
   * operation is being used while the controller is in a state that doesn't
   * support that operation.
   */
  @Immutable
  public static final class InconsistentStateException extends IllegalStateException {
    private final AuthnState actualState;
    private final AuthnState[] expectedStates;

    private InconsistentStateException(AuthnState actualState, AuthnState[] expectedStates) {
      super();
      this.actualState = actualState;
      this.expectedStates = expectedStates;
    }

    @Override
    public String getMessage() {
      StringBuilder buffer = new StringBuilder();
      buffer.append("Authentication session in wrong state: ");
      buffer.append(actualState);
      buffer.append(" ");
      if (expectedStates.length == 0) {
        buffer.append("not allowed here");
      } else {
        buffer.append("but should be ");
        if (expectedStates.length > 1) {
          buffer.append("one of ");
        }
        buffer.append(expectedStates[0]);
        for (int i = 1; i < expectedStates.length; i += 1) {
          buffer.append(", ");
          buffer.append(expectedStates[i]);
        }
      }
      return buffer.toString();
    }
  }

  /**
   * Logs an incoming servlet request.
   *
   * @param request The incoming request.
   * @throws IOException if there is a problem parsing the request URL.
   */
  public void logIncomingRequest(HttpServletRequest request)
      throws IOException {
    logger.info(logMessage("Incoming " + request.getMethod() + " URL: "
            + HttpUtil.getRequestUrl(request, true).toString()
            + " request " + SessionUtil.findGsaRequestId(request)));
  }

  /**
   * Annotates a log message with this session's ID.
   *
   * @param message The log message to annotate.
   * @return The annotated log message.
   */
  public String logMessage(String message) {
    return SessionUtil.logMessage(sessionId, message);
  }

  @VisibleForTesting
  public synchronized void setForceControllerFailure(AuthnState state) {
    forceControllerFailure = state;
  }

  @GuardedBy("this")
  private void maybeFailForTest() {
    if (forceControllerFailure == state) {
      forceControllerFailure = null;
      throw new RuntimeException("Forced test failure.");
    }
  }

  public void setClientElement(
      CredentialsGathererElement clientElement) {
    this.clientElement = clientElement;
  }


  private void readObject(ObjectInputStream is)
      throws ClassNotFoundException, IOException {
    is.defaultReadObject();
    this.config = ConfigSingleton.getConfig();
  }
}
