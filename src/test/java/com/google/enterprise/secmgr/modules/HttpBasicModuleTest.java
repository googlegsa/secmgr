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

import static org.mockito.Mockito.when;

import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.config.AuthnMechBasic;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.http.DenyRule;
import com.google.enterprise.secmgr.http.DenyRule.TYPE;
import com.google.enterprise.secmgr.http.DenyRules;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.enterprise.secmgr.mock.MockBasicAuthServer;
import com.google.enterprise.secmgr.mock.MockIntegration;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import javax.annotation.concurrent.Immutable;
import javax.servlet.ServletException;
import org.mockito.Mockito;

/**
 * Tests for the {@link HttpBasicModule} class.
 */
@Immutable
public class HttpBasicModuleTest extends SecurityManagerTestCase {

  private static final String CONTEXT_URL = "http://localhost:8973/basic";

  private final HttpBasicModule module;
  private final MockIntegration integration;
  private final String sampleUrl;
  private final AuthnMechanism mech1;
  private final SecurityManagerConfig config;

  private DenyRules denyRules;
  private static final String CG_NAME = "ADG1";

  public HttpBasicModuleTest()
      throws IOException, ServletException {
    denyRules = Mockito.mock(DenyRules.class);
    module = new HttpBasicModule(denyRules);
    integration = MockIntegration.make();
    MockBasicAuthServer server = new MockBasicAuthServer.Server1(CONTEXT_URL);
    integration.addMockServer(server);
    sampleUrl = server.getSampleUrl();
    mech1 = AuthnMechBasic.make("mech1", sampleUrl);
    config = makeConfig(
        Lists.newArrayList(
            CredentialGroup.builder(CG_NAME, "ADG1 display", true, true, false)
            .addMechanism(mech1)
            .build()));
  }

  @Override
  public void setUp()
      throws Exception {
    super.setUp();
    when(denyRules.getRule(Mockito.anyString())).thenReturn(null);
    integration.reset();
    ConfigSingleton.setConfig(config);
  }

  public void testHttpAuthenticateGoodNoDenyRules()
      throws IOException {
    assertEquals(VerificationStatus.VERIFIED, tryCredentials("joe", "plumber"));
    assertEquals(VerificationStatus.VERIFIED, tryCredentials("chinese客人", "test1"));
  }

  public void testHttpAuthenticateGoodWithDeniedStatusCode() throws IOException {
    DenyRule denyRule = DenyRule.newBuilder().setRequestType(TYPE.GET).addStatusCode(200).build();
    when(denyRules.getRule(Mockito.anyString())).thenReturn(denyRule);
    assertEquals(VerificationStatus.REFUTED, tryCredentials("joe", "plumber"));
  }

  public void testHttpAuthenticateGoodWithDeniedHeader() throws IOException {
    DenyRule.Header header =
        DenyRule.Header.newBuilder()
            .setName("content-type")
            .setValue("text/html; charset=UTF-8")
            .build();
    DenyRule denyRule =
        DenyRule.newBuilder().setRequestType(TYPE.GET).addHeader(header).build();
    when(denyRules.getRule(Mockito.anyString())).thenReturn(denyRule);
    assertEquals(VerificationStatus.REFUTED, tryCredentials("joe", "plumber"));
  }

  public void testHttpAuthenticateGoodWithDeniedContent() throws IOException {
    DenyRule denyRule =
        DenyRule.newBuilder()
            .setRequestType(TYPE.GET)
            .addContent("You are the lucky winner of our content!!!")
            .build();
    when(denyRules.getRule(Mockito.anyString())).thenReturn(denyRule);
    assertEquals(VerificationStatus.REFUTED, tryCredentials("joe", "plumber"));
  }

  public void testHttpAuthenticateBad()
      throws IOException {
    assertEquals(VerificationStatus.REFUTED, tryCredentials("joe", "biden"));
  }

  private VerificationStatus tryCredentials(String username, String password)
      throws IOException {
    AuthnSession session = integration.makeSession();
    session.addCredentials(mech1, AuthnPrincipal.make(username, CG_NAME),
        CredPassword.make(password));
    return AuthnController.invokeModule(module, session.getView(mech1), session);
  }
}
