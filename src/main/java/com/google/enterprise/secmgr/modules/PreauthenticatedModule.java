// Copyright 2013 Google Inc.
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

package com.google.enterprise.secmgr.modules;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.logmanager.LogClientParameters;
import com.google.enterprise.secmgr.authncontroller.AuthnModule;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.config.AuthnMechPreauthenticated;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.inject.Singleton;

import java.io.IOException;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * A module that accept credentials as verified without checking since
 * it's from a trusted app.
 */
@Singleton
@Immutable
public final class PreauthenticatedModule implements AuthnModule {

  private static final Logger logger = Logger.getLogger(PreauthenticatedModule.class.getName());
  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());

  @Inject
  private PreauthenticatedModule() {
  }

  @Override
  public boolean willHandle(SessionView view) {
    return view.getMechanism() instanceof AuthnMechPreauthenticated;
  }

  @Override
  public AuthnSessionState authenticate(SessionView view)
      throws IOException {

    String username = view.getUsername();
    if (Strings.isNullOrEmpty(username)) {
      logger.fine("No user to preauthenticate.");
      return AuthnSessionState.empty();
    }

    String idToLog = LogClientParameters.recordUsernames
        ? username : LogClientParameters.ID_NOT_LOGGED;
    logger.info(view.logMessage("Preauthenticated user: %s", idToLog));
    gsaLogger.info(view.getRequestId(), "Secure search api preauthenticated user: " + idToLog);

    return ModuleUtil.standardAuthnResult(view, VerificationStatus.VERIFIED,
        (Strings.isNullOrEmpty(view.getPassword())
         ? ImmutableList.<Credential>of(view.getPrincipal())
         : view.getPrincipalAndPassword()), null);
  }
}
