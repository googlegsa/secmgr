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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.config.AuthnMechNtlm;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.http.HttpClientUtil;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.enterprise.secmgr.mock.MockHttpClient;
import com.google.enterprise.secmgr.mock.MockHttpTransport;
import com.google.enterprise.secmgr.mock.MockNtlmAuthServer;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

/**
 * Tests for the {@link NtlmModule} class.
 */
public class NtlmModuleTest extends SecurityManagerTestCase {

  private static final String SAMPLE_URL_1 = "http://localhost:8973/ntlm/";

  private final NtlmModule module;
  private final AuthnMechanism mech1;
  private final SecurityManagerConfig config;
  private static final String CG_NAME = "ADG1";

  private AuthnSession session;

  public NtlmModuleTest() {
    module = ConfigSingleton.getInstance(NtlmModule.class);
    mech1 = AuthnMechNtlm.make("mech1", SAMPLE_URL_1);
    config = makeConfig(
        ImmutableList.of(
            CredentialGroup.builder(CG_NAME, "ADG1 display", true, true, false)
            .addMechanism(mech1)
            .build()));
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    session = AuthnSession.newInstance(config);
    MockNtlmAuthServer server = new MockNtlmAuthServer(null, ImmutableMap.of("joe", "plumber"));
    MockHttpTransport transport = ConfigSingleton.getInstance(MockHttpTransport.class);
    transport.registerServlet(SAMPLE_URL_1, server);
    HttpClientUtil.setHttpClient(new MockHttpClient(transport));
  }

  public void testHttpAuthenticate() {
    assertEquals(VerificationStatus.VERIFIED, tryCredentials("joe", "plumber"));
    assertEquals(VerificationStatus.REFUTED, tryCredentials("joe", "biden"));
  }

  private VerificationStatus tryCredentials(String username, String password) {
    session.addCredentials(mech1,
        AuthnPrincipal.make(username, CG_NAME, "google.com"),
        CredPassword.make(password));
    return AuthnController.invokeModule(module, session.getView(mech1), session);
  }
}
