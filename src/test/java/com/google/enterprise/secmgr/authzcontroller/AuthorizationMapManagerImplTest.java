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

import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.AuthnMechBasic;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.AuthzMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.FlexAuthorizer;
import com.google.enterprise.secmgr.config.FlexAuthzRoutingTableEntry;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.mock.MockBasicAuthServer;
import com.google.enterprise.secmgr.mock.MockIntegration;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

import java.io.IOException;

import javax.servlet.ServletException;

/**
 * Unit tests for {@link AuthorizationMapManagerImpl}.
 */
public class AuthorizationMapManagerImplTest extends SecurityManagerTestCase {

  private static final String BASIC1_CONTEXT_URL = "http://localhost:8973/mockbasicauthserver1";
  private static final String BASIC2_SAMPLE_URL = BASIC1_CONTEXT_URL + "/sample2";
  private static final String BASIC3_CONTEXT_URL = "http://localhost:8973/mockbasicauthserver3";

  private static final String CG1 = CredentialGroup.DEFAULT_NAME;
  private static final String CG2 = "Gama";

  private final MockIntegration integration;
  private final String basic1SampleUrl;
  private final String basic3SampleUrl;
  private final AuthnMechanism mech1;
  private final AuthnMechanism mech2;
  private final SecurityManagerConfig config;
  private SessionSnapshot snapshot;

  public AuthorizationMapManagerImplTest()
      throws IOException, ServletException {
    integration = MockIntegration.make();

    MockBasicAuthServer server1 = new MockBasicAuthServer.Server1(BASIC1_CONTEXT_URL);
    integration.addMockServer(server1);
    basic1SampleUrl = server1.getSampleUrl();

    integration.getHttpTransport().registerServlet(BASIC2_SAMPLE_URL, server1);

    MockBasicAuthServer server3 = new MockBasicAuthServer.Server2(BASIC3_CONTEXT_URL);
    integration.addMockServer(server3);
    basic3SampleUrl = server3.getSampleUrl();

    mech1 = AuthnMechBasic.make("mech1", basic1SampleUrl);
    mech2 = AuthnMechBasic.make("mech2", basic3SampleUrl);
    config = makeConfig(
        ImmutableList.of(
            CredentialGroup.builder(CG1, CG1, false, false, false)
            .addMechanism(mech1)
            .build(),
            CredentialGroup.builder(CG2, CG2, false, false, false)
            .addMechanism(mech2)
            .build()));
  }

  @Override
  public void setUp()
      throws Exception {
    super.setUp();
    integration.reset();
    ConfigSingleton.setConfig(config);
    AuthnSession session = AuthnSession.getInstance(config);
    session.addVerification(mech1.getAuthority(),
        Verification.verified(Verification.NEVER_EXPIRES,
            AuthnPrincipal.make("joe", CG1),
            CredPassword.make("plumber")));
    session.addVerification(mech2.getAuthority(),
        Verification.verified(Verification.NEVER_EXPIRES,
            AuthnPrincipal.make("joe", CG2),
            CredPassword.make("biden")));
    session.setRequestId("testRequest");
    snapshot = session.getSnapshot();
  }

  /**
   * Inject the flex authz config as a constructed data structure.
   */
  public void testConstructedConfig()
      throws IOException {
    commonPart(
        makeFlexAuthorizer(AuthzMechanism.HEADREQUEST, AuthzMechanism.HEADREQUEST),
        makeExpected(AuthzStatus.PERMIT, AuthzStatus.PERMIT, AuthzStatus.PERMIT));
  }

  /**
   * Check that updating the configuration changes the behavior.
   */
  public void testConfigUpdate()
      throws IOException {
    commonPart(
        makeFlexAuthorizer(AuthzMechanism.HEADREQUEST, AuthzMechanism.HEADREQUEST),
        makeExpected(AuthzStatus.PERMIT, AuthzStatus.PERMIT, AuthzStatus.PERMIT));
    commonPart(
        makeFlexAuthorizer(AuthzMechanism.HEADREQUEST, AuthzMechanism.DENY),
        makeExpected(AuthzStatus.PERMIT, AuthzStatus.PERMIT, AuthzStatus.DENY));
  }

  private void commonPart(FlexAuthorizer flexAuthorizer, AuthzResult expected)
      throws IOException {
    ConfigSingleton.getConfig().setFlexAuthorizer(flexAuthorizer);
    AuthzResult actual
        = integration.getAuthzController().authorize(
            Resource.urlsToResourcesNoAcls(expected.keySet()), snapshot, false);
    assertEquals(expected, actual);
  }

  private FlexAuthorizer makeFlexAuthorizer(AuthzMechanism mech1, AuthzMechanism mech2) {
    FlexAuthzRule rule1 = new FlexAuthzRule(CG1, mech1, "rule1", FlexAuthzRule.NO_TIME_LIMIT);
    FlexAuthzRule rule2 = new FlexAuthzRule(CG2, mech2, "rule2", FlexAuthzRule.NO_TIME_LIMIT);
    FlexAuthorizer flexAuthorizer = ConfigSingleton.getInstance(FlexAuthorizer.class);
    flexAuthorizer.addToRulesTable(rule1);
    flexAuthorizer.addToRulesTable(rule2);
    flexAuthorizer.addToRoutingTable(new FlexAuthzRoutingTableEntry(basic1SampleUrl, rule1));
    flexAuthorizer.addToRoutingTable(new FlexAuthzRoutingTableEntry(BASIC2_SAMPLE_URL, rule1));
    flexAuthorizer.addToRoutingTable(new FlexAuthzRoutingTableEntry(basic3SampleUrl, rule2));
    return flexAuthorizer;
  }

  private AuthzResult makeExpected(AuthzStatus status1, AuthzStatus status2, AuthzStatus status3) {
    return AuthzResult.builder()
        .put(basic1SampleUrl, status1)
        .put(BASIC2_SAMPLE_URL, status2)
        .put(basic3SampleUrl, status3)
        .build();
  }
}
