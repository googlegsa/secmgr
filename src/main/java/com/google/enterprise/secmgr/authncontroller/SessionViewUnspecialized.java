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

import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.AuthnMechPreauthenticated;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.CredentialGroup;

import java.util.List;
import java.util.logging.Logger;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * A view of a session snapshot that's not specialized.
 */
@Immutable
@ParametersAreNonnullByDefault
final class SessionViewUnspecialized extends SessionView {
  private static final Logger logger = Logger.getLogger(SessionViewUnspecialized.class.getName());

  SessionViewUnspecialized(final SessionSnapshot snapshot) {
    super(snapshot);
  }

  @Override
  protected SessionView withNewSnapshot(SessionSnapshot snapshot) {
    return snapshot.getView();
  }

  @Override
  public boolean isUnspecialized() {
    return true;
  }

  @Override
  public AuthnAuthority getAuthority() {
    throw new UnsupportedOperationException();
  }

  @Override
  public CredentialGroup getCredentialGroup() {
    throw new UnsupportedOperationException();
  }

  @Override
  public AuthnMechanism getMechanism() {
    throw new UnsupportedOperationException();
  }

  @Override
  protected Predicate<AuthnAuthority> getCookieFilter() {
    return Predicates.alwaysTrue();
  }

  @Override
  protected Predicate<AuthnAuthority> getCredentialFilter() {
    return Predicates.alwaysTrue();
  }

  @Override
  public boolean isSatisfied(boolean haveRunCredentialsGatherers) {
    List<CredentialGroup> nonEmpty = Lists.newArrayList();
    for (CredentialGroup credentialGroup : snapshot.getConfig().getCredentialGroups()) {
      // groups module is always present in all cred groups.
      if (credentialGroup.getMechanisms().size() > 1) {
        nonEmpty.add(credentialGroup);
      }
    }
    if (nonEmpty.isEmpty()) {
      logger.info(
          logMessage("No non-empty credential groups, so nothing to be satisfied."));
      return false;
    }

    boolean hasTrust = false;
    boolean satisfied = true;
    for (CredentialGroup credentialGroup : nonEmpty) {
      if (!snapshot.getView(credentialGroup).isSatisfied(haveRunCredentialsGatherers)) {
        logger.info(
            logMessage("Credential group %s reports not satisfied, so session is not satisfied.",
                credentialGroup.getName()));
        satisfied = false;
      } else {
        for (AuthnMechanism mech : credentialGroup.getMechanisms()) {
          if (AuthnMechPreauthenticated.TYPE_NAME == mech.getTypeName()) {
            hasTrust = true;
          }
        }
      }
    }
    return hasTrust || satisfied;
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append("{SessionView of ");
    builder.append(snapshot);
    builder.append("}");
    return builder.toString();
  }
}
