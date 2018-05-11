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
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.config.AuthnMechBasic;
import com.google.enterprise.secmgr.config.AuthnMechLdap;
import com.google.enterprise.secmgr.config.AuthnMechNtlm;
import com.google.enterprise.secmgr.config.AuthnMechPreauthenticated;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.json.ProxyTypeAdapter;
import com.google.enterprise.secmgr.json.TypeAdapters;
import com.google.enterprise.secmgr.json.TypeProxy;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.util.HashSet;
import java.util.Objects;
import java.util.logging.Logger;

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * This is the state exported from the security manager to the GSA after a
 * successful authentication.  It is also the format that the security manager
 * accepts from client SAML providers if they choose to provide this
 * information.
 */
@Immutable
@ParametersAreNonnullByDefault
public final class ExportedState {

  private static final Logger logger = Logger.getLogger(ExportedState.class.getName());

  @Nonnull public static final String ATTRIBUTE_NAME = "SecurityManagerState";
  @Nonnegative public static final int CURRENT_VERSION = 1;
  @Nonnegative public static final int MIN_VERSION = 1;
  @Nonnegative public static final int MAX_VERSION = 1;

  /**
   * This class represents simple credentials without the complex structure used
   * by the security manager.
   */
  @Immutable
  @ParametersAreNonnullByDefault
  public static final class Credentials {
    @Nonnull public static final Credentials EMPTY
        = new Credentials(null, null, null, null, ImmutableSet.<Group>of());

    @Nullable private final String username;
    @Nullable private final String domain;
    @Nullable private final String password;
    @Nullable private final String namespace;
    @Nonnull private final ImmutableSet<Group> groups;

    private Credentials(@Nullable String username, @Nullable String domain,
        @Nullable String password, @Nullable String namespace, ImmutableSet<Group> groups) {
      this.username = username;
      this.domain = domain;
      this.password = password;
      this.namespace = namespace;
      this.groups = groups;
    }

    /**
     * Gets a new credentials instance.
     *
     * @param username The username credential or {@code null}.
     * @param domain The domain credential or {@code null}.
     * @param password The password credential or {@code null}.
     * @param namespace The namespace credential or {@code null}.
     * @param groups The group credentials.
     * @return An immutable structure of the given credentials.
     */
    @Nonnull
    public static Credentials make(@Nullable String username, @Nullable String domain,
        @Nullable String password, @Nullable String namespace, Iterable<Group> groups) {
      return new Credentials(username, domain, password, namespace, ImmutableSet.copyOf(groups));
    }

    /**
     * Gets a new credentials instance with no groups.
     *
     * @param username The username credential or {@code null}.
     * @param domain The domain credential or {@code null}.
     * @param password The password credential or {@code null}.
     * @param namespace The namespace credential or {@code null}.
     * @return An immutable structure of the given credentials.
     */
    @Nonnull
    public static Credentials make(@Nullable String username, @Nullable String domain,
        @Nullable String password, @Nullable String namespace) {
      return make(username, domain, password, namespace, ImmutableSet.<Group>of());
    }

    /**
     * Gets this instance's username.
     */
    @Nullable
    public String getUsername() {
      return username;
    }

    /**
     * Gets this instance's domain.
     */
    @Nullable
    public String getDomain() {
      return domain;
    }

    /**
     * Gets this instance's namespace.
     */
    @Nullable
    public String getNamespace() {
      return namespace;
    }

    /**
     * Gets this instance's password.
     */
    @Nullable
    public String getPassword() {
      return password;
    }

    /**
     * Gets this instance's groups as an immutable set.
     */
    @Nonnull
    public ImmutableSet<Group> getGroups() {
      return groups;
    }

    @Override
    public boolean equals(Object object) {
      if (object == this) { return true; }
      if (!(object instanceof Credentials)) { return false; }
      Credentials other = (Credentials) object;
      return Objects.equals(getUsername(), other.getUsername())
          && Objects.equals(getDomain(), other.getDomain())
          && Objects.equals(getNamespace(), other.getNamespace())
          && Objects.equals(getPassword(), other.getPassword())
          && Objects.equals(getGroups(), other.getGroups());
    }

    @Override
    public int hashCode() {
      return Objects.hash(getUsername(), getDomain(), getNamespace(), 
                              getPassword(), getGroups());
    }

    @Override
    public String toString() {
      return ConfigSingleton.getGson().toJson(this);
    }

    private static final class LocalProxy implements TypeProxy<Credentials> {
      String username;
      String domain;
      String password;
      String name_space;  // For ease of use when transformed to json, proto in C++.
      ImmutableSet<Group> groups;

      @SuppressWarnings("unused")
      LocalProxy() {
      }

      @SuppressWarnings("unused")
      LocalProxy(Credentials credentials) {
        username = credentials.getUsername();
        domain = credentials.getDomain();
        name_space = credentials.getNamespace();
        password = credentials.getPassword();
        groups = credentials.getGroups();
      }

      @Override
      public Credentials build() {
        return Credentials.make(username, domain, password, name_space, groups);
      }
    }
  }

  @Nonnegative private final int version;
  @Nonnegative private final long timeStamp;
  @Nonnull private final AuthnSessionState sessionState;
  @Nonnull private final Credentials pviCredentials;
  @Nonnull private final Credentials basicCredentials;
  @Nonnull private final ImmutableList<Credentials> verifiedCredentials;
  @Nonnull private final ImmutableSet<GCookie> cookies;

  private ExportedState(@Nonnegative int version, @Nonnegative long timeStamp,
      AuthnSessionState sessionState, Credentials pviCredentials, Credentials basicCredentials,
      ImmutableList<Credentials> verifiedCredentials,
      ImmutableSet<GCookie> cookies) {
    this.version = version;
    this.timeStamp = timeStamp;
    this.sessionState = sessionState;
    this.pviCredentials = pviCredentials;
    this.basicCredentials = basicCredentials;
    this.verifiedCredentials = verifiedCredentials;
    this.cookies = cookies;
  }

  /**
   * Makes an exported-state object from a given session snapshot.
   *
   * @param snapshot A snapshot to derive the exported state from.
   * @return A corresponding exported-state object.
   */
  @Nonnull
  public static ExportedState make(SessionSnapshot snapshot) {
    long timeStamp = snapshot.getTimeStamp();
    // we keep track of "groupsAlreadyUsed" as a way of preventing the
    // generation of a large number of duplicate groups in the ExportedState.
    // instead, we carefully decide to place the groups we see into the first
    // eligible verifiedCredential as the container for these groups.
    // see more about this issue on b/12019644
    HashSet<Group> groupsAlreadyUsed = new HashSet<Group>();

    // verifiedCredentials is the high-priority for populating groups
    // because pviCredentials is going away soon
    ImmutableList.Builder<Credentials> verifiedCredentialsBuilder = ImmutableList.builder();
    for (SessionView view : snapshot.getAllVerifiedViews()) {
      verifiedCredentialsBuilder.add(
          credentialsForView(view, Credentials.EMPTY, groupsAlreadyUsed));
    }
    ImmutableList<Credentials> verifiedCredentials = verifiedCredentialsBuilder.build();

    Credentials pviCredentials = credentialsForView(
        snapshot.getPrimaryVerifiedView(), Credentials.EMPTY, groupsAlreadyUsed);
    Credentials basicCredentials = credentialsForView(
        getBasicView(snapshot), copyCredentialsWithoutGroups(pviCredentials), groupsAlreadyUsed);
    logger.info("Total of " + groupsAlreadyUsed.size() + " groups in ExportedState.");

    ImmutableSet<GCookie> cookies = ImmutableSet.copyOf(snapshot.getView().getAuthorityCookies());
    return new ExportedState(CURRENT_VERSION, timeStamp, snapshot.getState(), pviCredentials,
        basicCredentials, verifiedCredentials, cookies);
  }

  private static Credentials copyCredentialsWithoutGroups(Credentials source) {
    return Credentials.make(source.getUsername(), source.getDomain(), source.getPassword(),
        source.getNamespace(), new HashSet<Group>());
  }

  /**
   * Returns a Credentials object representing the given SessionView, but
   * without any groups that have been already previously used / added from
   * a different view.
   */
  private static Credentials credentialsForView(SessionView view, Credentials fallback,
      HashSet<Group> groupsAlreadyUsed) {
    if (view == null) {
      return fallback;
    }
    if (view.hasVerifiedPrincipalAndPassword()) {

      return createCredential(view, groupsAlreadyUsed, true);
    }
    if (view.hasVerifiedPrincipal()) {
      return createCredential(view, groupsAlreadyUsed, false);
    }
    return Credentials.EMPTY;
  }

  /**
   * Creates a Credentials object with or without a password, for a SessionView
   * that excludes the passed in set of groups already used.
   */
  private static Credentials createCredential(SessionView view, HashSet<Group> groupsAlreadyUsed,
      boolean hasPassword) {
    HashSet<Group> groupsToAdd = new HashSet<Group>();
    for (Group group : view.getGroups()) {
      if (!groupsAlreadyUsed.contains(group)) {
        groupsToAdd.add(group);
        groupsAlreadyUsed.add(group);
      }
    }
    return Credentials.make(view.getUsername(), view.getDomain(),
        hasPassword ? view.getPassword() : null, view.getNamespace(), groupsToAdd);
  }

  private static SessionView getBasicView(SessionSnapshot snapshot) {
    for (AuthnMechanism mechanism : snapshot.getConfig().getMechanisms()) {
      if (mechanism instanceof AuthnMechBasic
          || mechanism instanceof AuthnMechLdap
          || mechanism instanceof AuthnMechNtlm
          || mechanism instanceof AuthnMechPreauthenticated) {
        return snapshot.getView(mechanism);
      }
    }
    return null;
  }

  /**
   * Gets the time at which this state was frozen.
   */
  @Nonnegative
  public long getTimeStamp() {
    return timeStamp;
  }

  /**
   * Gets the security manager's session state, consisting of all cookies,
   * credentials, and verifications generated during authentication.
   */
  @Nonnull
  public AuthnSessionState getSessionState() {
    return sessionState;
  }

  /**
   * Gets the credentials for the Primary Verified Identity (PVI).
   */
  @Nonnull
  public Credentials getPviCredentials() {
    return pviCredentials;
  }

  /**
   * If the security manager is configured for HTTP Basic or NTLM
   * authentication, this gets the credentials for that mechanism.
   */
  @Nonnull
  public Credentials getBasicCredentials() {
    return basicCredentials;
  }

  /**
   * Returns all non-connector verified credentials from the security manager,
   * or an empty list if there is none.
   */
  @Nonnull
  public ImmutableList<Credentials> getAllVerifiedCredentials() {
    return verifiedCredentials;
  }

  /**
   * Gets all the cookies collected by the security manager.
   */
  @Nonnull
  public ImmutableSet<GCookie> getCookies() {
    return cookies;
  }

  /**
   * Gets a JSON string representation for this object.
   */
  @Nonnull
  public String toJsonString() {
    return ConfigSingleton.getGson().toJson(this);
  }

  /**
   * Decodes a JSON string representation into an exported-state object.
   */
  @Nonnull
  public static ExportedState fromJsonString(String jsonString) {
    return ConfigSingleton.getGson().fromJson(jsonString, ExportedState.class);
  }

  static void registerTypeAdapters(GsonBuilder builder) {
    builder.registerTypeAdapter(Credentials.class,
        ProxyTypeAdapter.make(Credentials.class, Credentials.LocalProxy.class));
    builder.registerTypeAdapter(ExportedState.class,
        ProxyTypeAdapter.make(ExportedState.class, LocalProxy.class));
    builder.registerTypeAdapter(new TypeToken<ImmutableSet<String>>() {}.getType(),
        TypeAdapters.immutableSet());
    builder.registerTypeAdapter(new TypeToken<ImmutableSet<GCookie>>() {}.getType(),
        TypeAdapters.immutableSet());
    builder.registerTypeAdapter(new TypeToken<ImmutableList<Credentials>>() {}.getType(),
        TypeAdapters.immutableList());
  }

  private static final class LocalProxy implements TypeProxy<ExportedState> {
    int version;
    long timeStamp;
    AuthnSessionState sessionState;
    Credentials pviCredentials;
    Credentials basicCredentials;
    ImmutableList<Credentials> verifiedCredentials;
    ImmutableSet<GCookie> cookies;

    @SuppressWarnings("unused")
    LocalProxy() {
    }

    @SuppressWarnings("unused")
    LocalProxy(ExportedState state) {
      version = state.version;
      timeStamp = state.timeStamp;
      sessionState = state.getSessionState();
      pviCredentials = state.getPviCredentials();
      basicCredentials = state.getBasicCredentials();
      verifiedCredentials = state.getAllVerifiedCredentials();
      cookies = state.getCookies();
    }

    @Override
    public ExportedState build() {
      Preconditions.checkArgument(version >= MIN_VERSION && version <= MAX_VERSION);
      Preconditions.checkArgument(timeStamp >= 0);
      Preconditions.checkArgument(sessionState != null);
      return new ExportedState(version, timeStamp, sessionState, pviCredentials, basicCredentials,
          ImmutableList.copyOf(verifiedCredentials), ImmutableSet.copyOf(cookies));
    }
  }
}
