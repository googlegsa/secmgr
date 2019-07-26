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

import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.config.AuthnMechPreauthenticated;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.enterprise.secmgr.mock.MockIntegration;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

import java.io.IOException;

import javax.annotation.concurrent.Immutable;
import javax.servlet.ServletException;

/**
 * Tests for the {@link PreauthenticatedModule} class.
 */
@Immutable
public class PreauthenticatedModuleTest extends SecurityManagerTestCase {

  private static final String CONTEXT_URL = "http://localhost:8973/basic";

  private final PreauthenticatedModule module;
  private final MockIntegration integration;
  private final AuthnMechanism mech1;
  private final SecurityManagerConfig config;
  private static final String CG_NAME = "ADG1";

  public PreauthenticatedModuleTest()
      throws IOException, ServletException {
    module = ConfigSingleton.getInstance(PreauthenticatedModule.class);
    integration = MockIntegration.make();
    mech1 = AuthnMechPreauthenticated.make("mech1");
    config = makeConfig(
        Lists.newArrayList(
            CredentialGroup.builder(CG_NAME, "ADG1 display", false, false, true)
            .addMechanism(mech1)
            .build()));
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    integration.reset();
    ConfigSingleton.setConfig(config);
  }

  public void testAuthenticate()
      throws IOException {
    assertEquals(VerificationStatus.VERIFIED, tryCredentials("joe", "plumber"));
  }

  private VerificationStatus tryCredentials(String username, String password)
      throws IOException {
    AuthnSession session = integration.makeSession();
    session.addCredentials(mech1, AuthnPrincipal.make(username, CG_NAME),
        CredPassword.make(password));
    return AuthnController.invokeModule(module, session.getView(mech1), session);
  }
}
