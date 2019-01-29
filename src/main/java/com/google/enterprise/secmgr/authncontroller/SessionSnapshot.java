// Copyright 2011 Google Inc.
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
import com.google.common.collect.ImmutableCollection;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.Verification;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import org.joda.time.DateTimeUtils;
import org.joda.time.format.ISODateTimeFormat;

import java.net.URL;
import java.util.Map;

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletRequest;

/**
 * An immutable snapshot of the session's state.
 */
@Immutable
@ParametersAreNonnullByDefault
public final class SessionSnapshot implements Serializable {
  @Nonnull private final String sessionId;
  @Nullable private final String requestId;
  //TODO: Replace this with an immutable info.
  @Nullable private final HttpServletRequest request;
  @Nonnull transient private SecurityManagerConfig config;
  @Nullable private final URL authnEntryUrl;
  @Nonnull private final ImmutableCollection<GCookie> userAgentCookies;
  @Nonnull private final AuthnSessionState state;
  @Nonnegative private final long timeStamp;
  @Nonnull private final SessionView unspecializedView;
  @GuardedBy("itself")
  @Nonnull private final Map<AuthnMechanism, SessionView> savedMechanismViews;
  @GuardedBy("itself")
  @Nonnull private final Map<CredentialGroup, SessionView> savedCredentialGroupViews;

  private SessionSnapshot(String sessionId, String requestId, HttpServletRequest request,
      SecurityManagerConfig config,
      @Nullable URL authnEntryUrl, ImmutableCollection<GCookie> userAgentCookies,
      AuthnSessionState state, @Nonnegative long timeStamp) {
    this.sessionId = sessionId;
    this.requestId = requestId;
    this.request = request;
    this.config = config;
    this.authnEntryUrl = authnEntryUrl;
    this.userAgentCookies = userAgentCookies;
    this.state = state;
    this.timeStamp = timeStamp;
    unspecializedView = SessionView.create(this);
    savedMechanismViews = Maps.newHashMap();
    savedCredentialGroupViews = Maps.newHashMap();
  }

  static SessionSnapshot make(String sessionId, String requestId, HttpServletRequest request,
      SecurityManagerConfig config, @Nullable URL authnEntryUrl,
      ImmutableCollection<GCookie> userAgentCookies, AuthnSessionState state) {
    return new SessionSnapshot(sessionId, requestId, request, config, authnEntryUrl,
        userAgentCookies, state, DateTimeUtils.currentTimeMillis());
  }

  @VisibleForTesting
  public static SessionSnapshot make(SecurityManagerConfig config, AuthnSessionState state) {
    return make(SessionUtil.generateId(), SessionUtil.generateId(), null, config, null,
        ImmutableList.<GCookie>of(), state);
  }

  SessionSnapshot withNewUserAgentCookies(ImmutableCollection<GCookie> userAgentCookies) {
    return new SessionSnapshot(sessionId, requestId, request, config, authnEntryUrl,
        userAgentCookies, state, timeStamp);
  }

  @Nonnull
  public String getSessionId() {
    return sessionId;
  }

  @Nullable
  public String getRequestId() {
    return requestId;
  }

  @Nullable
  public HttpServletRequest getRequest() {
    return request;
  }

  @Nonnull
  public SecurityManagerConfig getConfig() {
    return config;
  }

  @Nullable
  URL getAuthnEntryUrl() {
    return authnEntryUrl;
  }

  @Nonnull
  ImmutableCollection<GCookie> getUserAgentCookies() {
    return userAgentCookies;
  }

  @Nonnull
  public AuthnSessionState getState() {
    return state;
  }

  @Nonnegative
  long getTimeStamp() {
    return timeStamp;
  }

  /**
   * Gets a view of this snapshot specialized for a given authentication
   * mechanism.
   *
   * @param mechanism An authentication mechanism.
   * @return A mechanism view of this snapshot.
   */
  @Nonnull
  public SessionView getView(AuthnMechanism mechanism) {
    synchronized (savedMechanismViews) {
      SessionView view = savedMechanismViews.get(mechanism);
      if (view == null) {
        view = SessionView.create(this, mechanism);
        savedMechanismViews.put(mechanism, view);
      }
      return view;
    }
  }

  /**
   * Gets a view of this snapshot specialized for a given credential group.
   *
   * @param credentialGroup A credential group.
   * @return A credential-group view of this snapshot.
   */
  @Nonnull
  public SessionView getView(CredentialGroup credentialGroup) {
    synchronized (savedCredentialGroupViews) {
      SessionView view = savedCredentialGroupViews.get(credentialGroup);
      if (view == null) {
        view = SessionView.create(this, credentialGroup);
        savedCredentialGroupViews.put(credentialGroup, view);
      }
      return view;
    }
  }

  /**
   * Gets an unspecialized view of this snapshot.
   *
   * @return An unspecialized view of this snapshot.
   */
  @Nonnull
  public SessionView getView() {
    return unspecializedView;
  }

  /**
   * Gets the expiration time for this snapshot.
   *
   * @return The expiration time.
   */
  public long getExpirationTime() {
    SessionView view = getView();
    return view.isSatisfied(true)
        ? Verification.minimumExpirationTime(view.getVerifications())
        : timeStamp;
  }

  /**
   * Get a "primary verified view".  This is a view containing a principal
   * that's been verified, with preference given to the default credential
   * group's view, if possible.
   *
   * <p>The primary verified view is intended for use by the GSA, and this
   * method is only called when generating output for the GSA.  It should
   * <b>never</b> be used for any other purpose.
   *
   * @return The primary verified view, or null if there isn't one.
   */
  public SessionView getPrimaryVerifiedView() {
    SessionView winner = null;
    for (CredentialGroup credentialGroup : getConfig().getCredentialGroups()) {
      SessionView view = getView(credentialGroup);
      if (view.hasVerifiedPrincipal()) {
        if (credentialGroup.isDefault()) {
          return view;
        }
        if (winner == null) {
          winner = view;
        }
      }
    }
    return winner;
  }

  /**
   * Get all verified views.  These will be views containing a principal
   * that's been verified.
   *
   * @return a iterable of all verified views.  This iterable may be empty.
   */
  public Iterable<SessionView> getAllVerifiedViews() {
    ImmutableList.Builder<SessionView> builder = ImmutableList.builder();
    for (CredentialGroup credentialGroup : getConfig().getCredentialGroups()) {
      SessionView view = getView(credentialGroup);
      if (view.hasVerifiedPrincipal()) {
        builder.add(view);
      }
    }
    return builder.build();
  }

  @Nonnull
  public String logMessage(String format, Object... args) {
    return SessionUtil.logMessage(sessionId, String.format(format, args));
  }

  /**
   * Gets a log-message decorator that decorates with this view's session ID.
   *
   * @return The log-message decorator.
   */
  @Nonnull
  public Decorator getLogDecorator() {
    return SessionUtil.getLogDecorator(getSessionId());
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append("{SessionSnapshot taken at ");
    builder.append(ISODateTimeFormat.dateTime().print(timeStamp));
    builder.append(" of session ");
    builder.append(sessionId);
    builder.append("}");
    return builder.toString();
  }

  private void readObject(ObjectInputStream is)
      throws ClassNotFoundException, IOException {
    is.defaultReadObject();
    this.config = ConfigSingleton.getConfig();
  }
}
