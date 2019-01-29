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

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.IdentityUtil;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.AuthnMechConnector;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.AuthzMechanism;
import com.google.enterprise.secmgr.config.ConfigParams;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.ConnMgrInfo;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.enterprise.secmgr.config.ParamName;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.http.ConnectorUtil;
import com.google.enterprise.secmgr.http.HttpClientUtil;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.enterprise.secmgr.mock.MockCMAuthServer;
import com.google.enterprise.secmgr.mock.MockCMAuthServer.Authorizer;
import com.google.enterprise.secmgr.mock.MockGetConnectorInstanceList;
import com.google.enterprise.secmgr.mock.MockHttpClient;
import com.google.enterprise.secmgr.mock.MockHttpTransport;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Unit tests for {@link ConnectorModule}.
 */
public class ConnectorModuleTest extends SecurityManagerTestCase {
  private static final Logger logger = Logger.getLogger(ConnectorModuleTest.class.getName());

  private static final String CM1_NAME = "myConnectorManager1";
  private static final String CM1_URL = "http://myConnectorManager1.example.com";
  private static final String CM2_NAME = "myConnectorManager2";
  private static final String CM2_URL = "http://myConnectorManager2.example.com";
  private static final String CONNECTOR11_NAME = "myConnector11";
  private static final String CONNECTOR12_NAME = "myConnector12";
  private static final String CONNECTOR21_NAME = "myConnector21";
  private static final String CONNECTOR22_NAME = "myConnector22";
  private static final String CONNECTOR31_NAME = "myConnector31";
  private static final String USERNAME1 = "joe";
  private static final String DOMAIN1 = "republicans";
  private static final String PASSWORD1 = "plumber";
  private static final String USERNAME2 = "jim";
  private static final String PASSWORD2 = "biden";
  private static final String DOMAIN2 = "democrats";
  private static final String USERNAME3 = "jack";
  private static final String GROUP1 = "eng";
  private static final String GROUP11 = GROUP1 + "@" + DOMAIN1;
  private static final String GROUP2 = "lp";
  private static final String GROUP22 = DOMAIN2 + "\\" + GROUP2;
  private static final String GROUP3 = MockCMAuthServer.LOCAL_GROUP_PREFIX 
                                       + "/[local_domain]local_group";
  private static final String CG1 = "group1";
  private static final String CG2 = "group2";

  private static final String URL1 = "http://example.com/foo/bar";
  private static final ImmutableList<String> ACL1 =
      ImmutableList.of(IdentityUtil.joinNameDomain(USERNAME1, DOMAIN1));
  private static final String URL2 = "http://google.com/baz/mumble";
  private static final ImmutableList<String> ACL2 =
      ImmutableList.of(IdentityUtil.joinNameDomain(USERNAME2, DOMAIN2));
  private static final String URL3 = "http://notgoogle.com/whatever";
  private static final ImmutableList<String> ACL3 = ImmutableList.of(USERNAME3);

  private static final FlexAuthzRule authzRule11 =
      new FlexAuthzRule("authzRule11", AuthzMechanism.CONNECTOR,
          ImmutableMap.of(FlexAuthzRule.ParamName.CONNECTOR_NAME, CONNECTOR11_NAME),
          "authzRule11", FlexAuthzRule.NO_TIME_LIMIT);
  private static final FlexAuthzRule authzRule12 =
      new FlexAuthzRule("authzRule12", AuthzMechanism.CONNECTOR,
          ImmutableMap.of(FlexAuthzRule.ParamName.CONNECTOR_NAME, CONNECTOR12_NAME),
          "authzRule12", FlexAuthzRule.NO_TIME_LIMIT);
  private static final FlexAuthzRule authzRule21 =
      new FlexAuthzRule("authzRule21", AuthzMechanism.CONNECTOR,
          ImmutableMap.of(FlexAuthzRule.ParamName.CONNECTOR_NAME, CONNECTOR21_NAME),
          "authzRule21", FlexAuthzRule.NO_TIME_LIMIT);
  private static final FlexAuthzRule authzRule22 =
      new FlexAuthzRule("authzRule22", AuthzMechanism.CONNECTOR,
          ImmutableMap.of(FlexAuthzRule.ParamName.CONNECTOR_NAME, CONNECTOR22_NAME),
          "authzRule22", FlexAuthzRule.NO_TIME_LIMIT);
  private static final FlexAuthzRule authzRule31 =
      new FlexAuthzRule("authzRule31", AuthzMechanism.CONNECTOR,
          ImmutableMap.of(FlexAuthzRule.ParamName.CONNECTOR_NAME, CONNECTOR31_NAME),
          "authzRule31", FlexAuthzRule.NO_TIME_LIMIT);

  private final AuthnMechConnector mech11;
  private final AuthnMechConnector mech12;
  private final AuthnMechConnector mech21;
  private final AuthnMechConnector mech22;
  private final SecurityManagerConfig config;
  private final ConnectorModule module;
  private AuthnSession session;
  private MockCMAuthServer cmAuthServer1;
  private MockCMAuthServer cmAuthServer2;

  public ConnectorModuleTest(String name) {
    super(name);
    mech11 = AuthnMechConnector.make("mech11", CONNECTOR11_NAME, false);
    mech12 = AuthnMechConnector.make("mech12", CONNECTOR12_NAME, true);
    mech21 = AuthnMechConnector.make("mech21", CONNECTOR21_NAME, false);
    mech22 = AuthnMechConnector.make("mech22", CONNECTOR22_NAME, false);
    config = makeConfig(
        ImmutableList.of(
            CredentialGroup.builder(CG1, CG1 + " display", false, false, false)
            .addMechanism(mech11)
            .addMechanism(mech12)
            .build(),
            CredentialGroup.builder(CG2, CG2 + " display", false, false, false)
            .addMechanism(mech21)
            .addMechanism(mech22)
            .build()));
    module = ConfigSingleton.getInstance(ConnectorModule.class);
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    session = AuthnSession.newInstance(config);
    MockHttpTransport transport = ConfigSingleton.getInstance(MockHttpTransport.class);
    HttpClientUtil.setHttpClient(new MockHttpClient(transport));

    cmAuthServer1 = new MockCMAuthServer();
    cmAuthServer1.setPassword(CONNECTOR11_NAME, USERNAME1, DOMAIN1, PASSWORD1);
    cmAuthServer1.setPassword(CONNECTOR12_NAME, USERNAME1, DOMAIN1, PASSWORD1);
    cmAuthServer1.addGroup(CONNECTOR11_NAME, USERNAME1, DOMAIN1, GROUP11);
    cmAuthServer1.addGroup(CONNECTOR12_NAME, USERNAME1, DOMAIN1, GROUP22);
    cmAuthServer1.addGroup(CONNECTOR11_NAME, USERNAME1, DOMAIN1, GROUP3);
    LocalAuthorizer authorizer1 = new LocalAuthorizer();
    authorizer1.setAcl(URL1, CONNECTOR11_NAME, ACL1);
    authorizer1.setAcl(URL1, CONNECTOR12_NAME, ACL1);
    authorizer1.setAcl(URL3, CONNECTOR11_NAME, ACL3);
    cmAuthServer1.setAuthorizer(authorizer1);
    transport.registerServlet(
        CM1_URL + ConnectorUtil.CM_AUTHENTICATE_SERVLET_PATH,
        cmAuthServer1);
    transport.registerServlet(
        CM1_URL + ConnectorUtil.CM_AUTHORIZATION_SERVLET_PATH,
        cmAuthServer1);
    transport.registerServlet(
        CM1_URL + ConnectorUtil.CM_INSTANCE_LIST_SERVLET_PATH,
        new MockGetConnectorInstanceList(ImmutableList.of(CONNECTOR11_NAME, CONNECTOR12_NAME)));

    cmAuthServer2 = new MockCMAuthServer();
    cmAuthServer2.setPassword(CONNECTOR21_NAME, USERNAME2, DOMAIN2, PASSWORD2);
    cmAuthServer2.setPassword(CONNECTOR22_NAME, USERNAME1, DOMAIN1, PASSWORD1);
    LocalAuthorizer authorizer2 = new LocalAuthorizer();
    authorizer2.setAcl(URL2, CONNECTOR21_NAME, ACL2);
    authorizer2.setAcl(URL2, CONNECTOR22_NAME, ACL2);
    authorizer2.setAcl(URL3, CONNECTOR21_NAME, ACL3);
    cmAuthServer2.setAuthorizer(authorizer2);
    transport.registerServlet(
        CM2_URL + ConnectorUtil.CM_AUTHENTICATE_SERVLET_PATH,
        cmAuthServer2);
    transport.registerServlet(
        CM2_URL + ConnectorUtil.CM_AUTHORIZATION_SERVLET_PATH,
        cmAuthServer2);
    transport.registerServlet(
        CM2_URL + ConnectorUtil.CM_INSTANCE_LIST_SERVLET_PATH,
        new MockGetConnectorInstanceList(ImmutableList.of(CONNECTOR21_NAME, CONNECTOR22_NAME)));

    SecurityManagerConfig config = ConfigSingleton.getConfig();
    config.setParams(ConfigParams.builder(config.getParams())
        .put(ParamName.CONNECTOR_MANAGER_INFO,
            ConnMgrInfo.make(
                ImmutableList.of(
                    ConnMgrInfo.Entry.make(CM1_NAME, CM1_URL),
                    ConnMgrInfo.Entry.make(CM2_NAME, CM2_URL))))
        .build());
  }

  private final class LocalAuthorizer implements Authorizer {

    private final Map<String, List<String>> aclMap;

    public LocalAuthorizer() {
      aclMap = Maps.newHashMap();
    }

    public void setAcl(String url, String connectorName, List<String> acl) {
      aclMap.put(makeAclKey(url, connectorName), acl);
    }

    public AuthzStatus apply(String url, String connectorName, String username, String domain,
        String password) {
      List<String> acls = aclMap.get(makeAclKey(url, connectorName));
      if (acls == null) {
        return AuthzStatus.INDETERMINATE;
      }
      String key = IdentityUtil.joinNameDomain(username, domain);
      for (String id : acls) {
        if (id.equals(key)) {
          return AuthzStatus.PERMIT;
        }
      }
      return AuthzStatus.DENY;
    }

    private String makeAclKey(String url, String connectorName) {
      return Strings.nullToEmpty(connectorName) + "::" + url;
    }
  }

  public void testGood() {
    logger.info("start test");
    assertEquals(VerificationStatus.VERIFIED, tryAuthn(mech11, USERNAME1, CG1, 
        DOMAIN1, PASSWORD1));
  }

  public void testBadUsername() {
    logger.info("start test");
    assertEquals(VerificationStatus.REFUTED, tryAuthn(mech11, USERNAME2, CG1, 
        DOMAIN1, PASSWORD1));
  }

  public void testBadDomain() {
    logger.info("start test");
    assertEquals(VerificationStatus.REFUTED, tryAuthn(mech11, USERNAME1, CG1, 
        DOMAIN2, PASSWORD1));
  }

  public void testNoDomain() {
    logger.info("start test");
    assertEquals(VerificationStatus.REFUTED, tryAuthn(mech11, USERNAME1, CG1,
        null, PASSWORD1));
  }

  public void testBadPassword() {
    logger.info("start test");
    assertEquals(VerificationStatus.REFUTED, tryAuthn(mech11, USERNAME1, CG1, 
        DOMAIN1, PASSWORD2));
  }

  public void testGroupOnlyWithoutVerifiedPrincipal() {
    logger.info("start test");
    assertEquals(VerificationStatus.INDETERMINATE, tryAuthn(mech12, USERNAME1, CG1, 
        DOMAIN1));
  }

  public void testGroupGoodWithPassword() {
    logger.info("start test");
    assertEquals(VerificationStatus.VERIFIED, tryAuthn(mech11, USERNAME1, CG1, DOMAIN1, PASSWORD1));
    assertEquals(ImmutableSet.of(Group.make(GROUP1, MockCMAuthServer.DEFAULT_GROUPS_NS, DOMAIN1),
                                 Group.make(GROUP3, MockCMAuthServer.DEFAULT_GROUPS_NS)), 
                                 getGroups(mech11));
    assertEquals(VerificationStatus.VERIFIED, runAuthn(mech12));
    assertEquals(ImmutableSet.of(Group.make(GROUP1, MockCMAuthServer.DEFAULT_GROUPS_NS, DOMAIN1), 
                 Group.make(GROUP2, MockCMAuthServer.DEFAULT_GROUPS_NS, DOMAIN2),
                 Group.make(GROUP3, MockCMAuthServer.DEFAULT_GROUPS_NS)), 
                 getGroups(mech12));
  }

  public void testGroupGoodNoPassword() {
    logger.info("start test");
    assertEquals(VerificationStatus.INDETERMINATE, tryAuthn(mech11, USERNAME1, CG1, DOMAIN1));
    assertEquals(VerificationStatus.INDETERMINATE, tryAuthn(mech12, USERNAME1, CG1, DOMAIN1));
  }

  public void testGroupBadPassword() {
    logger.info("start test");
    assertEquals(VerificationStatus.REFUTED, tryAuthn(mech11, USERNAME1, CG1, DOMAIN1, PASSWORD2));
    assertEquals(ImmutableSet.<String>of(), getGroups(mech11));
  }

  public void testNoGroupLookup() {
    logger.info("start test");
    assertEquals(VerificationStatus.VERIFIED, tryAuthn(mech21, USERNAME2, CG1, DOMAIN2, PASSWORD2));
    assertEquals(ImmutableSet.<Group>of(), getGroups(mech21));
  }

  private VerificationStatus tryAuthn(AuthnMechanism mech, String username, 
      String namespace, String domain, String password) {
    addCreds(mech, username, namespace, domain, password);
    return runAuthn(mech);
  }

  // the no password case
  private VerificationStatus tryAuthn(AuthnMechanism mech, String username,
      String namespace, String domain) {
    addCreds(mech, username, namespace, domain);
    return runAuthn(mech);
  }

  private VerificationStatus runAuthn(AuthnMechanism mech) {
    return AuthnController.invokeModule(module, session.getView(mech), session);
  }

  public void testAuthz11() throws Exception {
    logger.info("start test");
    addVerification(mech11, USERNAME1, CG1, DOMAIN1, PASSWORD1);
    tryAuthz(mech11, authzRule11, 1, 0,
        ImmutableMap.of(
            URL1, AuthzStatus.PERMIT,
            URL2, AuthzStatus.INDETERMINATE,
            URL3, AuthzStatus.DENY));
    tryAuthz(mech11, authzRule12, 1, 0,
        ImmutableMap.of(
            URL1, AuthzStatus.PERMIT,
            URL2, AuthzStatus.INDETERMINATE,
            URL3, AuthzStatus.INDETERMINATE));
  }

  public void testAuthz12() throws Exception {
    logger.info("start test");
    addVerification(mech11, USERNAME1, CG1, DOMAIN1, PASSWORD1);
    tryAuthz(mech11, authzRule12, 1, 0,
        ImmutableMap.of(
            URL1, AuthzStatus.PERMIT,
            URL2, AuthzStatus.INDETERMINATE,
            URL3, AuthzStatus.INDETERMINATE));
  }

  public void testAuthz21() throws Exception {
    logger.info("start test");
    addVerification(mech21, USERNAME2, CG2, DOMAIN2, PASSWORD2);
    tryAuthz(mech21, authzRule21, 0, 1,
        ImmutableMap.of(
            URL1, AuthzStatus.INDETERMINATE,
            URL2, AuthzStatus.PERMIT,
            URL3, AuthzStatus.DENY));
  }

  public void testAuthz22() throws Exception {
    logger.info("start test");
    addVerification(mech21, USERNAME2, CG2, DOMAIN2, PASSWORD2);
    tryAuthz(mech21, authzRule22, 0, 1,
        ImmutableMap.of(
            URL1, AuthzStatus.INDETERMINATE,
            URL2, AuthzStatus.PERMIT,
            URL3, AuthzStatus.INDETERMINATE));
  }

  // Test behavior when connector name is unknown.
  public void testAuthz31() throws Exception {
    logger.info("start test");
    addVerification(mech21, USERNAME2, CG2, DOMAIN2, PASSWORD2);
    tryAuthz(mech21, authzRule31, 0, 0,
        ImmutableMap.of(
            URL1, AuthzStatus.INDETERMINATE,
            URL2, AuthzStatus.INDETERMINATE,
            URL3, AuthzStatus.INDETERMINATE));
  }

  public void testNoVerification() throws Exception {
    logger.info("start test");
    addCreds(mech21, USERNAME2, CG2, DOMAIN2, PASSWORD2);
    // In testAuthz21, the results are different.
    tryAuthz(mech21, authzRule21, 0, 0,
        ImmutableMap.of(
            URL1, AuthzStatus.INDETERMINATE,
            URL2, AuthzStatus.INDETERMINATE,
            URL3, AuthzStatus.INDETERMINATE));
  }

  private void tryAuthz(AuthnMechanism mech, FlexAuthzRule rule, int expectedCounter1,
      int expectedCounter2, Map<String, AuthzStatus> urlMap) throws Exception {
    Set<String> urls = urlMap.keySet();
    cmAuthServer1.resetAuthzCounter();
    cmAuthServer2.resetAuthzCounter();
    AuthzResult responses = getAuthzResponses(mech, rule, urls);
    assertNotNull("Null response from authorize()", responses);
    assertEquals(urls.size(), responses.size());
    for (String url : urls) {
      assertEquals(urlMap.get(url), findAuthzResponse(url, responses));
    }
    assertEquals(expectedCounter1, cmAuthServer1.getAuthzCounter());
    assertEquals(expectedCounter2, cmAuthServer2.getAuthzCounter());
  }

  private AuthzResult getAuthzResponses(AuthnMechanism mech, FlexAuthzRule rule, Set<String> urls) 
    throws Exception {
    return module.authorize(Resource.urlsToResourcesNoAcls(urls), session.getView(mech), rule);
  }

  private AuthzStatus findAuthzResponse(String url, AuthzResult responses) {
    AuthzStatus status = responses.get(url);
    if (status == null) {
      fail("Unable to find response for URL: " + url);
    }
    return status;
  }

  private void addCreds(AuthnMechanism mech, String username, String namespace,
      String domain, String password) {
    session.addCredentials(mech,
        AuthnPrincipal.make(username, namespace, domain),
        CredPassword.make(password));
  }

  // no password
  private void addCreds(AuthnMechanism mech, String username, String namespace,
      String domain) {
    session.addCredentials(mech,
        AuthnPrincipal.make(username, namespace, domain));
  }

  private void addVerification(AuthnMechanism mech, String username, String namespace,
      String domain, String password) {
    Credential credential = AuthnPrincipal.make(username, namespace, domain);
    session.addVerification(mech.getAuthority(),
        Verification.verified(Verification.NEVER_EXPIRES, credential));

    CredPassword pwd = CredPassword.make(password);
    session.addVerification(mech.getAuthority(),
        Verification.verified(Verification.NEVER_EXPIRES, pwd));
  }

  private Set<Group> getGroups(AuthnMechanism mech) {
    return session.getView(mech).getVerifiedGroups();
  }
}
