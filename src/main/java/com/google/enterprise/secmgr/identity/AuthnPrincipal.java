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

package com.google.enterprise.secmgr.identity;

import com.google.common.base.Preconditions;
import com.google.enterprise.secmgr.common.IdentityUtil;
import com.google.enterprise.secmgr.common.Stringify;
import com.google.enterprise.secmgr.config.CredentialTypeName;
import com.google.enterprise.secmgr.json.ProxyTypeAdapter;
import com.google.enterprise.secmgr.json.TypeProxy;
import com.google.gson.GsonBuilder;

import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * A credential that contains the user's name and optionally some domain info.
 *
 * A principal may be stored in an identity's credential set.  Doing so doesn't
 * imply that it's verified; that's true only if the identity has a verification
 * that explicitly includes the principal.
 *
 * @see Verification
 */
@Immutable
@ParametersAreNonnullByDefault
public final class AuthnPrincipal extends AbstractCredential
    implements java.security.Principal {

  @Nonnull private final String name;
  @Nonnull private final String namespace;
  @Nullable private final String domain;

  private AuthnPrincipal(String name, String namespace, @Nullable String domain) {
    super();
    Preconditions.checkNotNull(name);
    this.name = name;
    this.namespace = namespace;
    this.domain = domain;
  }

  /**
   * Makes a principal.
   *
   * @param name The principal's name; may not be null.
   * @param domain The domain name; may be null.
   * @return A principal with the given components.
   */
  @Nonnull
  public static AuthnPrincipal make(String name, String namespace,
      @Nullable String domain) {
    return new AuthnPrincipal(name, namespace, domain);
  }

  /**
   * Makes a principal with no domain.
   *
   * @param name The username.
   * @return A principal with the given username and no domain.
   */
  @Nonnull
  public static AuthnPrincipal make(String name, String namespace) {
    return new AuthnPrincipal(name, namespace, null);
  }

  /**
   * Gets the name associated with this identity.  Usually a "user name" or
   * "login name".
   *
   * @return The identity's name as a string.
   */
  @Nonnull
  public String getName() {
    return name;
  }

  /**
   * Gets the namespace associated with this identity.
   *
   * @return The namespace as a string.
   */
  public String getNamespace() {
    return namespace;
  }

  /**
   * Gets the domain name associated with this identity.
   *
   * @return The domain name as a string.
   */
  @Nullable
  public String getDomain() {
    return domain;
  }

  @Override
  public boolean isPublic() {
    return true;
  }

  @Override
  public CredentialTypeName getTypeName() {
    return CredentialTypeName.PRINCIPAL;
  }

  @Override
  public boolean isVerifiable() {
    return !name.isEmpty();
  }

  @Override
  public boolean equals(Object object) {
    if (object == this) { return true; }
    if (!(object instanceof AuthnPrincipal)) { return false; }
    AuthnPrincipal principal = (AuthnPrincipal) object;
    return Objects.equals(name, principal.getName())
        && Objects.equals(domain, principal.getDomain())
        && Objects.equals(namespace, principal.getNamespace());
  }

  @Override
  public int hashCode() {
    return Objects.hash(name, namespace, domain);
  }

  @Override
  public String toString() {
    return "{principal: " + namespace + ":" +
        Stringify.object(IdentityUtil.joinNameDomain(name, domain)) + "}";
  }

  static void registerTypeAdapters(GsonBuilder builder) {
    builder.registerTypeAdapter(AuthnPrincipal.class,
        ProxyTypeAdapter.make(AuthnPrincipal.class, LocalProxy.class));
  }

  private static final class LocalProxy implements TypeProxy<AuthnPrincipal> {
    String name;
    String namespace;
    String domain;

    @SuppressWarnings("unused")
    LocalProxy() {
    }

    @SuppressWarnings("unused")
    LocalProxy(AuthnPrincipal principal) {
      name = principal.getName();
      namespace = principal.getNamespace();
      domain = principal.getDomain();
    }

    @Override
    public AuthnPrincipal build() {
      return make(name, namespace, domain);
    }
  }

  /**
   * Parses a string into a principal.
   *
   * @param string The combined username/domain string.
   * @param namespace The namespace of this username/domain string.
   * @return A principal with the separated username, namespace and domain.
   * @see IdentityUtil#parseNameAndDomain
   */
  @Nonnull
  public static AuthnPrincipal parse(String string, String namespace) {
    String[] parsed = IdentityUtil.parseNameAndDomain(string);
    return make(parsed[0], namespace, parsed[1]);
  }
}
