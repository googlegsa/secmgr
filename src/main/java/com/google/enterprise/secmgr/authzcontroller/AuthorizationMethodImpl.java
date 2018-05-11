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

package com.google.enterprise.secmgr.authzcontroller;

import com.google.common.base.Preconditions;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.AuthzMechanism;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.enterprise.secmgr.modules.AuthzModule;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.inject.assistedinject.Assisted;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.Collection;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * An implementation of an authorization method.  Adapts an authorization module
 * and a flexible authorization rule to the authorization method interface.
 */
@Immutable
@ParametersAreNonnullByDefault
public final class AuthorizationMethodImpl implements AuthorizationMethod {
  private static final Logger logger = Logger.getLogger(AuthorizationMethodImpl.class.getName());
  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());

  private final AuthzModule module;
  private final FlexAuthzRule rule;

  @Inject
  private AuthorizationMethodImpl(@Assisted AuthzModule module, @Assisted FlexAuthzRule rule) {
    Preconditions.checkNotNull(module);
    Preconditions.checkNotNull(rule);
    this.module = module;
    this.rule = rule;
  }

  @Override
  public AuthzResult authorize(Collection<Resource> resources, SessionSnapshot snapshot) {
    Preconditions.checkNotNull(resources);
    Preconditions.checkNotNull(snapshot);

    AuthzMechanism mech = rule.getAuthzMechType();

    SessionView view = getView(rule.getAuthnId(), snapshot);
    if (view == null) {
      logger.warning(snapshot.logMessage("Unknown authentication ID: %s", rule.getAuthnId()));
      return abort(Resource.resourcesToUrls(resources), snapshot);
    }
    AuthzResult result;
    try {
      result = module.authorize(resources, view, rule);
    } catch (InterruptedIOException e) {
      logger.warning(snapshot.logMessage("Authorization timed out: %s", e.getMessage()));
      gsaLogger.log(view.getRequestId(), "Authorization module timed out: " + e.getMessage());
      return abort(Resource.resourcesToUrls(resources), snapshot);
    } catch (IOException e) {
      logger.log(Level.WARNING, snapshot.logMessage("Error while authorizing: "), e);
      return abort(Resource.resourcesToUrls(resources), snapshot);
    }
    logResult(result, snapshot);
    return result;
  }

  private SessionView getView(String authnId, SessionSnapshot snapshot) {
    if (authnId.equalsIgnoreCase(FlexAuthzRule.EMPTY_CONNECTOR_NAME)) {
      return snapshot.getView();
    }
    for (CredentialGroup group : snapshot.getConfig().getCredentialGroups()) {
      if (authnId.equalsIgnoreCase(group.getName())) {
        return snapshot.getView(group);
      }
      for (AuthnMechanism mech : group.getMechanisms()) {
        if (authnId.equalsIgnoreCase(mech.getName())) {
          return snapshot.getView(mech);
        }
      }
    }
    return null;
  }

  private AuthzResult abort(Collection<String> resourceUrls, SessionSnapshot snapshot) {
    AuthzResult result = AuthzResult.makeIndeterminate(resourceUrls);
    logResult(result, snapshot);
    return result;
  }

  private void logResult(AuthzResult result, SessionSnapshot snapshot) {
    LogClient.BatchLogger batchLogger = gsaLogger.getBatchLogger();
    int i = 1;
    for (Map.Entry<String, AuthzStatus> entry : result.entrySet()) {
      if (entry.getValue() != AuthzStatus.INDETERMINATE) {
        logger.info(snapshot.logMessage("%s by %s: %s",
            entry.getValue().getDescription(),
            rule.getAuthzMechType(),
            entry.getKey()));

        batchLogger.log(snapshot.getRequestId(), String.format("%s by %s: %s",
            entry.getValue().getDescription(),
            rule.getAuthzMechType(),
            entry.getKey()));
      }
      i++;
    }
    batchLogger.send();
  }

  @Override
  public String getName() {
    return rule.getRowDisplayName();
  }

  @Override
  public int getTimeout() {
    return rule.getTimeout();
  }

  @Override
  public boolean equals(Object object) {
    if (object == this) { return true; }
    if (!(object instanceof AuthorizationMethod)) { return false; }
    AuthorizationMethod other = (AuthorizationMethod) object;
    return getName().equals(other.getName());
  }

  @Override
  public int hashCode() {
    return getName().hashCode();
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append("{name:");
    builder.append(getName());
    builder.append(", class:");
    builder.append(this.getClass().getSimpleName());
    builder.append("}");
    return builder.toString();
  }
}
