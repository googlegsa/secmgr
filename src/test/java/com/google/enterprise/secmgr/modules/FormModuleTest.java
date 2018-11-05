// Copyright 2008 Google Inc.
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

import com.google.common.collect.Iterables;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.enterprise.secmgr.mock.MockIntegration;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

import java.io.IOException;

import javax.annotation.concurrent.Immutable;
import javax.servlet.ServletException;

/**
 * Unit tests for {@link FormModule}.
 */
@Immutable
public class FormModuleTest extends SecurityManagerTestCase {

  private final AuthnMechanism mech;
  private final String namespace;
  private final MockIntegration integration;
  private final FormModule module;

  public FormModuleTest(String name)
      throws IOException, ServletException {
    super(name);
    namespace = ConfigSingleton.getConfig().getCredentialGroups().get(0).getName();
    mech = ConfigSingleton.getConfig().getCredentialGroups().get(0).getMechanisms().get(0);
    integration = MockIntegration.make();
    module = ConfigSingleton.getInstance(FormModule.class);
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    integration.reset();
  }

  public void testGood()
      throws IOException {
    assertTrue(tryCreds("joe", "plumber"));
  }

  public void testBadPassword()
      throws IOException {
    assertFalse(tryCreds("joe", "biden"));
  }

  public void testEmptyUsername()
      throws IOException {
    assertFalse(tryCreds("", "plumber"));
  }

  public void testEmptyPassword()
      throws IOException {
    assertFalse(tryCreds("joe", ""));
  }

  public void testBadUsername()
      throws IOException {
    assertFalse(tryCreds("jim", "plumber"));
  }

  public boolean tryCreds(String username, String password)
      throws IOException {
    AuthnSession session = integration.makeSession();
    session.addCredentials(mech, AuthnPrincipal.make(username, namespace), 
                           CredPassword.make(password));
    FormModule connector = ConfigSingleton.getInstance(FormModule.class);
    VerificationStatus status
        = AuthnController.invokeModule(module, session.getView(mech), session);
    return status == VerificationStatus.VERIFIED
        && !Iterables.isEmpty(session.getView(mech).getAuthorityCookies());
  }
}
