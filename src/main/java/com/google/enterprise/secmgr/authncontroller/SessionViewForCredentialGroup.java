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
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;

import java.util.logging.Logger;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * A view of a session snapshot that's specialized for a credential group.
 */
@Immutable
@ParametersAreNonnullByDefault
final class SessionViewForCredentialGroup extends SessionView {
  private static final Logger logger
      = Logger.getLogger(SessionViewForCredentialGroup.class.getName());

  @Nonnull private final CredentialGroup credentialGroup;

  SessionViewForCredentialGroup(SessionSnapshot snapshot, CredentialGroup credentialGroup) {
    super(snapshot);
    Preconditions.checkNotNull(credentialGroup);
    Preconditions.checkState(
        snapshot.getConfig().getCredentialGroups().contains(credentialGroup));
    this.credentialGroup = credentialGroup;
  }

  @Override
  protected SessionView withNewSnapshot(SessionSnapshot snapshot) {
    return snapshot.getView(credentialGroup);
  }

  @Override
  public boolean isSpecializedForCredentialGroup() {
    return true;
  }

  @Override
  public AuthnAuthority getAuthority() {
    return credentialGroup.getAuthority();
  }

  @Override
  public AuthnMechanism getMechanism() {
    throw new UnsupportedOperationException();
  }

  @Override
  public CredentialGroup getCredentialGroup() {
    return credentialGroup;
  }

  @Override
  protected Predicate<AuthnAuthority> getCookieFilter() {
    return snapshot.getConfig().getAuthorityPredicate(credentialGroup);
  }

  @Override
  protected Predicate<AuthnAuthority> getCredentialFilter() {
    return snapshot.getConfig().getAuthorityPredicate(credentialGroup);
  }

  @Override
  public boolean isSatisfied(boolean haveRunCredentialsGatherers) {
    if (credentialGroup.getMechanisms().size() <= 1) {
      // An empty group is never satisfied. Post 7.0, a cred group is never empty.
      // It has atleast one mechanism (groups).
      logger.info(
          logMessage("Credential group %s not satisfied because it is empty.",
              credentialGroup.getName()));
      return false;
    }

    if (isRefuted()) {
      logger.info(
          logMessage("Credential group %s not satisfied because it is refuted.",
              credentialGroup.getName()));
      return false;
    }

    // If the group is optional, then it's satisfied if we've tried to get
    // credentials for the group and they have not been supplied.  In the case
    // of credential groups that use the ULF, we look for an empty principal and
    // password, which indicates we have run the ULF and that the user didn't
    // file them in.  For credential groups that don't use the ULF, we use
    // haveRunCredentialsGatherers to make this decision.
    logger.fine("is optional " + credentialGroup.getIsOptional()
                + " has request " + (getRequest() != null)
                + " has run gatherers " + haveRunCredentialsGatherers);
    if (credentialGroup.getIsOptional()
        && ((getRequest() != null && haveRunCredentialsGatherers)
        || (credentialGroup.canUseUlfCredentials()
            ? hasEmptyPrincipal() && hasEmptyPassword()
            : haveRunCredentialsGatherers))) {
      logger.info(
          logMessage("Credential group %s satisfied because it's optional and was left blank.",
              credentialGroup.getName()));
      return true;
    }

    // If principal is required, it must be present and non-empty.
    if (credentialGroup.getRequiresUsername() && !hasVerifiedPrincipal()) {
      logger.info(
          logMessage("Credential group %s not satisfied because it requires a username.",
              credentialGroup.getName()));
      return false;
    }

    // If password is required, it must be present and non-empty.
    if (credentialGroup.getRequiresPassword() && !hasVerifiedPassword()) {
      logger.info(
          logMessage("Credential group %s not satisfied because it requires a password.",
              credentialGroup.getName()));
      return false;
    }

    // TODO: This doesn't check the credentials -- so the username and/or
    // password might not be verified.  Unfortunately, the program's current
    // logic doesn't understand that credentials must be verified independently
    // of the satisfaction of their identity group.
    if (!isVerified()) {
      logMessage("Credential group %s not satisfied because it isn't verified.",
          credentialGroup.getName());
      return false;
    }

    return true;
  }

  private boolean hasEmptyPrincipal() {
    AuthnPrincipal principal = getPrincipal();
    return principal != null && principal.getName().isEmpty();
  }

  private boolean hasEmptyPassword() {
    CredPassword password = getPasswordCredential();
    return password != null && password.getText().isEmpty();
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append("{SessionView of ");
    builder.append(snapshot);
    builder.append(" specialized for: ");
    builder.append(credentialGroup);
    builder.append("}");
    return builder.toString();
  }
}
