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

import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableCollection;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.GroupMemberships;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.identity.VerificationStatus;

import java.net.URL;

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletRequest;

/**
 * A view of a session snapshot that may be specialized or unspecialized.
 */
@Immutable
@ParametersAreNonnullByDefault
public abstract class SessionView {

  @Nonnull protected final SessionSnapshot snapshot;
  @GuardedBy("this") @Nullable protected AuthnSessionState.Summary summary;

  protected SessionView(SessionSnapshot snapshot) {
    Preconditions.checkNotNull(snapshot);
    this.snapshot = snapshot;
    summary = null;
  }

  /**
   * Creates a session view specialized for a given authentication mechanism.
   *
   * @param snapshot The session snapshot the view is a specialization of.
   * @param mechanism The authentication mechanism to specialize for.
   * @return A view of the snapshot specialized for the mechanism.
   */
  @Nonnull
  static SessionView create(SessionSnapshot snapshot, AuthnMechanism mechanism) {
    return new SessionViewForMechanism(snapshot, mechanism);
  }

  /**
   * Creates a session view specialized for a given credential group.
   *
   * @param snapshot The session snapshot the view is a specialization of.
   * @param credentialGroup The credential group to specialize for.
   * @return A view of the snapshot specialized for the credential group.
   */
  @Nonnull
  static SessionView create(SessionSnapshot snapshot, CredentialGroup credentialGroup) {
    return new SessionViewForCredentialGroup(snapshot, credentialGroup);
  }

  /**
   * Creates an unspecialized session view.
   *
   * @param snapshot The session snapshot the view is a specialization of.
   * @return An unspecialized view of the snapshot.
   */
  @Nonnull
  static SessionView create(SessionSnapshot snapshot) {
    return new SessionViewUnspecialized(snapshot);
  }

  /**
   * Gets a new view identical to this one except that it contains the given
   * user-agent cookies.  Used to update a view after returning from a
   * credentials gatherer.
   *
   * @param userAgentCookies The new user-agent cookies.
   * @return A new view as specified.
   */
  @Nonnull
  SessionView withNewUserAgentCookies(ImmutableCollection<GCookie> userAgentCookies) {
    return withNewSnapshot(snapshot.withNewUserAgentCookies(userAgentCookies));
  }

  @Nonnull
  protected abstract SessionView withNewSnapshot(SessionSnapshot snapshot);

  /**
   * Is this a mechanism view?
   *
   * @return True only if this view is specialized for an authentication mechanism.
   */
  public boolean isSpecializedForMechanism() {
    return false;
  }

  /**
   * Is this a credential-group view?
   *
   * @return True only if this view is specialized for a credential group.
   */
  public boolean isSpecializedForCredentialGroup() {
    return false;
  }

  /**
   * Is this an unspecialized view?
   *
   * @return True only if this is an unspecialized view.
   */
  public boolean isUnspecialized() {
    return false;
  }

  /**
   * Gets a summary of the view's session state.
   */
  @Nonnull
  public synchronized AuthnSessionState.Summary getSummary() {
    if (summary == null) {
      summary = snapshot.getState().computeSummary(snapshot.getConfig().getCredentialGroups());
    }
    return summary;
  }

  /**
   * Gets the session ID string.
   *
   * @return The session ID string.
   */
  @Nonnull
  public String getSessionId() {
    return snapshot.getSessionId();
  }

  @Nullable
  public String getRequestId() {
    return snapshot.getRequestId();
  }

  @Nullable
  public HttpServletRequest getRequest() {
    return snapshot.getRequest();
  }

  /**
   * Gets the URL that initiated the current authentication request.
   *
   * @return The authentication request URL, or null if we're not processing an
   *     authentication request.
   */
  @Nullable
  public URL getAuthnEntryUrl() {
    return snapshot.getAuthnEntryUrl();
  }

  /**
   * Gets the URL that initiated the current authentication request.
   *
   * @return The authentication request URL as a string, or null if we're not
   *     processing an authentication request.
   */
  @Nullable
  public String getAuthnEntryUrlString() {
    return getAuthnEntryUrl().toString();
  }

  /**
   * Gets the time at which this view's snapshot was taken.
   *
   * @return The snapshot time in milliseconds since the epoch.
   */
  @Nonnegative
  public long getTimeStamp() {
    return snapshot.getTimeStamp();
  }

  /**
   * Gets this view's authority, if it is a specialized view.
   *
   * @return The authority.
   * @throws UnsupportedOperationException if this is not a specialized view.
   */
  @Nonnull
  public abstract AuthnAuthority getAuthority();

  /**
   * Gets this view's credential group, if this is a specialized view.
   *
   * @return The credential group.
   * @throws UnsupportedOperationException if this is not a specialized view.
   */
  @Nonnull
  public abstract CredentialGroup getCredentialGroup();

  /**
   * Gets this view's mechanism, if this is a mechanism view.
   *
   * @return The mechanism associated with this view.
   * @throws UnsupportedOperationException if this is not a mechanism view.
   */
  @Nonnull
  public abstract AuthnMechanism getMechanism();

  /**
   * Is this view's credential group required to have a principal?
   *
   * @return True if a principal is required.
   * @throws UnsupportedOperationException if this is not a specialized view.
   */
  public boolean getRequiresPrincipal() {
    return getCredentialGroup().getRequiresUsername();
  }

  /**
   * Gets the configured expiration time.
   *
   * @return The expiration time.
   * @throws UnsupportedOperationException if this is not a mechanism view.
   */
  public long getConfiguredExpirationTime() {
    long trustDuration = getMechanism().getTrustDuration();
    return (trustDuration > 0)
        ? snapshot.getTimeStamp() + trustDuration
        : Verification.EXPIRES_AFTER_REQUEST;
  }

  protected abstract Predicate<AuthnAuthority> getCookieFilter();
  protected abstract Predicate<AuthnAuthority> getCredentialFilter();

  /**
   * Is this view satisfied?
   *
   * @param haveRunCredentialsGatherers If credentials gatherers have been run.
   */
  public abstract boolean isSatisfied(boolean haveRunCredentialsGatherers);

  // **************** Cookies ****************

  /**
   * Gets the cookies that were received from the user agent in the most recent
   * HTTP request.
   *
   * @return The cookies.
   */
  @Nonnull
  public Iterable<GCookie> getUserAgentCookies() {
    return snapshot.getUserAgentCookies();
  }

  /**
   * Gets a user-agent cookie by name.  Note that there can be multiple such
   * cookies; in that case one is chosen arbitrarily.
   *
   * @param name The name of the cookie to get.
   * @return A cookie with that name, or {@code null} if none.
   */
  @Nullable
  public GCookie getUserAgentCookie(String name) {
    Preconditions.checkNotNull(name);
    for (GCookie cookie : getUserAgentCookies()) {
      if (name.equals(cookie.getName())) {
        return cookie;
      }
    }
    return null;
  }

  /**
   * Gets the cookies that have been received from this view's authorities.
   *
   * @return An immutable set of the authority cookies.
   */
  @Nonnull
  public ImmutableSet<GCookie> getAuthorityCookies() {
    return getSummary().getCookies(getCookieFilter(), getTimeStamp());
  }

  // **************** Credentials ****************

  /**
   * Gets the credentials that have been gathered for this view.
   *
   * @return An immutable set of the credentials.
   */
  public ImmutableSet<Credential> getCredentials() {
    return getSummary().getCredentials(getCredentialFilter());
  }

  /**
   * Gets this view's principal.
   *
   * @return The principal, or {@code null} if there isn't one.
   */
  @Nullable
  public AuthnPrincipal getPrincipal() {
    return getUniqueCredential(AuthnPrincipal.class);
  }

  /**
   * Gets this view's password credential.
   *
   * @return The password credential, or {@code null} if there isn't one.
   */
  @Nullable
  public CredPassword getPasswordCredential() {
    return getUniqueCredential(CredPassword.class);
  }

  /**
   * Gets this view's group-memberships credential.
   *
   * @return The group-memberships credential, or {@code null} if there isn't one.
   */
  @Nullable
  public GroupMemberships getGroupMemberships() {
    return getUniqueCredential(GroupMemberships.class);
  }

  private <T extends Credential> T getUniqueCredential(Class<T> clazz) {
    Credential uniqueCredential = null;
    for (Credential credential : getCredentials()) {
      if (clazz.isInstance(credential)) {
        if (uniqueCredential == null) {
          uniqueCredential = credential;
        } else if (!uniqueCredential.equals(credential)) {
          return null;
        }
      }
    }
    return clazz.cast(uniqueCredential);
  }

  /**
   * Gets a groups-membership credential that contains some given groups as well
   * as any others that have already been gathered.
   *
   * @param groups Some groups to add.
   * @return A groups-membership credential.
   */
  @Nonnull
  public GroupMemberships extendGroupMemberships(Iterable<Group> groups) {
    GroupMemberships previous = getGroupMemberships();
    return (previous == null)
        ? GroupMemberships.make(groups)
        : GroupMemberships.make(groups, previous);
  }

  /**
   * Does this view have a principal and a password?
   *
   * @return True if the view has exactly one principal and one password.
   */
  public boolean hasPrincipalAndPassword() {
    return hasPrincipalAndPassword(getPrincipal(), getPasswordCredential());
  }

  private boolean hasPrincipalAndPassword(AuthnPrincipal principal, CredPassword password) {
    return principal != null
        && !principal.getName().isEmpty()
        && password != null
        && !password.getText().isEmpty();
  }

  /**
   * Gets this view's principal and password.
   *
   * @return An immutable collection containing those credentials.
   * @throws IllegalStateException unless both are available.
   */
  @Nonnull
  public ImmutableCollection<Credential> getPrincipalAndPassword() {
    AuthnPrincipal principal = getPrincipal();
    CredPassword password = getPasswordCredential();
    Preconditions.checkState(hasPrincipalAndPassword(principal, password));
    return ImmutableList.<Credential>of(principal, password);
  }

  /**
   * Gets this view's username.
   *
   * @return The username, or {@code null} if there isn't one.
   */
  @Nullable
  public String getUsername() {
    AuthnPrincipal principal = getPrincipal();
    return (principal != null) ? principal.getName() : null;
  }

  /**
   * Gets this view's namespace.
   *
   * @return The namespace, or {@code null} if there isn't one.
   */
  @Nullable
  public String getNamespace() {
    AuthnPrincipal principal = getPrincipal();
    return (principal != null) ? principal.getNamespace() : null;
  }

  /**
   * Gets this view's domain.
   *
   * @return The domain, or {@code null} if there isn't one.
   */
  @Nullable
  public String getDomain() {
    AuthnPrincipal principal = getPrincipal();
    return (principal != null) ? principal.getDomain() : null;
  }

  /**
   * Gets this view's password.
   *
   * @return The password, or {@code null} if there isn't one.
   */
  @Nullable
  public String getPassword() {
    CredPassword password = getPasswordCredential();
    return (password != null) ? password.getText() : null;
  }

  /**
   * Gets this view's groups.
   *
   * @return The groups, as an immutable set.
   */
  @Nullable
  public ImmutableSet<Group> getGroups() {
    GroupMemberships groups = getGroupMemberships();
    return (groups != null) ? groups.getGroups() : ImmutableSet.<Group>of();
  }

  // **************** Verifications ****************

  /**
   * Gets the verifications for this view.
   *
   * @return An immutable set of this view's verifications.
   */
  @Nonnull
  public ImmutableSet<Verification> getVerifications() {
    return getSummary().getVerifications(getCredentialFilter(), getTimeStamp());
  }

  /**
   * Does this view have a verified principal?
   *
   * @return True if this view has at least one verification containing a
   *     principal, and if no other verification contains a different principal.
   */
  public boolean hasVerifiedPrincipal() {
    return null != getUniqueVerifiedCredential(AuthnPrincipal.class);
  }

  /**
   * Does this view have a verified password?
   *
   * @return True if this view has at least one verification containing a
   *     password, and if no other verification contains a different password.
   */
  public boolean hasVerifiedPassword() {
    return null != getUniqueVerifiedCredential(CredPassword.class);
  }

  /**
   * Does this view have a jointly verified principal and password?
   *
   * @return True if this view has at least one verification containing both a
   *     principal and password, and if no other verification contains a
   *     different principal or password.
   */
  public boolean hasVerifiedPrincipalAndPassword() {
    AuthnPrincipal principal = getUniqueVerifiedCredential(AuthnPrincipal.class);
    CredPassword password = getUniqueVerifiedCredential(CredPassword.class);
    return principal != null
        && password != null
        && areJointlyVerified(principal, password);
  }

  /**
   * Gets a verified principal.
   *
   * @return The verified principal.  Returns {@code null} if
   *     {@code hasVerifiedPrincipal()} is false.
   */
  @Nullable
  public AuthnPrincipal getVerifiedPrincipal() {
    return getUniqueVerifiedCredential(AuthnPrincipal.class);
  }

  /**
   * Gets a verified password.
   *
   * @return The verified password.  Returns {@code null} if
   *     {@code hasVerifiedPassword()} is false.
   */
  @Nullable
  public CredPassword getVerifiedPassword() {
    return getUniqueVerifiedCredential(CredPassword.class);
  }

  /**
   * Gets the verified groups for this view.
   *
   * @return The verified groups, may be empty.
   */
  @Nonnull
  public ImmutableSet<Group> getVerifiedGroups() {
    ImmutableSet.Builder<Group> builder = ImmutableSet.builder();
    for (GroupMemberships credential : getVerifiedCredentials(GroupMemberships.class)) {
      builder.addAll(credential.getGroups());
    }
    return builder.build();
  }

  /**
   * Gets the expiration time of a credential.
   *
   * @param credential A credential to get the expiration time for.
   * @return The credential's expiration time, or {@code 0} if the credential
   *     isn't verified.
   */
  public long getCredentialExpirationTime(Credential credential) {
    Preconditions.checkNotNull(credential);
    return Verification.maximumExpirationTime(getJointVerifications(credential));
  }

  private <T extends Credential> T getUniqueVerifiedCredential(Class<T> clazz) {
    Credential uniqueCredential = null;
    for (Verification verification : getVerifications()) {
      if (verification.isVerified()) {
        for (Credential credential : verification.getCredentials()) {
          if (clazz.isInstance(credential)) {
            if (uniqueCredential == null) {
              uniqueCredential = credential;
            } else if (!uniqueCredential.equals(credential)) {
              return null;
            }
          }
        }
      }
    }
    return clazz.cast(uniqueCredential);
  }

  private <T extends Credential> Iterable<T> getVerifiedCredentials(Class<T> clazz) {
    ImmutableList.Builder<T> builder = ImmutableList.builder();
    for (Verification verification : getVerifications()) {
      if (verification.isVerified()) {
        for (Credential credential : verification.getCredentials()) {
          if (clazz.isInstance(credential)) {
            builder.add(clazz.cast(credential));
          }
        }
      }
    }
    return builder.build();
  }

  private boolean areJointlyVerified(Credential... credentials) {
    return Iterables.any(getVerifications(), jointVerificationPredicate(credentials));
  }

  private Iterable<Verification> getJointVerifications(Credential... credentials) {
    return Iterables.filter(getVerifications(), jointVerificationPredicate(credentials));
  }

  private Predicate<Verification> jointVerificationPredicate(Credential... credentials) {
    final ImmutableList<Credential> copy = ImmutableList.copyOf(credentials);
    return new Predicate<Verification>() {
      @Override
      public boolean apply(Verification verification) {
        return verification.isVerified()
            && verification.getCredentials().containsAll(copy);
      }
    };
  }

  /**
   * Gets this view's verification status.
   *
   * @return The verification status.
   */
  @Nonnull
  public VerificationStatus getVerificationStatus() {
    return Verification.getStatus(getVerifications());
  }

  /**
   * Does this view have no refutations and at least one verification?
   *
   * @return True if this view is verified.
   */
  public boolean isVerified() {
    return getVerificationStatus() == VerificationStatus.VERIFIED;
  }

  /**
   * Does this view have at least one refutation?
   *
   * @return True if this view is refuted.
   */
  public boolean isRefuted() {
    return getVerificationStatus() == VerificationStatus.REFUTED;
  }

  /**
   * Does this view have no refutations and no verifications?
   *
   * @return True if this view is indeterminate.
   */
  public boolean isIndeterminate() {
    return getVerificationStatus() == VerificationStatus.INDETERMINATE;
  }

  // **************** Logging ****************

  /**
   * Decorates a log message with this view's session ID.
   *
   * @param format The format string to pass to {@link String#format}.
   * @param args The arguments to pass to {@link String#format}.
   * @return The decorated log message.
   */
  @Nonnull
  public String logMessage(String format, Object... args) {
    return snapshot.logMessage(format, args);
  }

  /**
   * Gets a log-message decorator that decorates with this view's session ID.
   *
   * @return The log-message decorator.
   */
  @Nonnull
  public Decorator getLogDecorator() {
    return snapshot.getLogDecorator();
  }
}
