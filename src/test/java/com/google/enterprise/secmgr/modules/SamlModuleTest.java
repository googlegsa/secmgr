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
import com.google.common.collect.ImmutableMultimap;
import com.google.common.collect.Multimap;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.AuthnMechSaml;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.AuthzMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.enterprise.secmgr.config.FlexAuthzRule.ParamName;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.http.HttpClientUtil;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.GroupMemberships;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.mock.AuthorizeByAcl;
import com.google.enterprise.secmgr.mock.AuthorizeByThirdParty;
import com.google.enterprise.secmgr.mock.AuthorizeWithCredential;
import com.google.enterprise.secmgr.mock.MockHttpClient;
import com.google.enterprise.secmgr.mock.MockHttpTransport;
import com.google.enterprise.secmgr.mock.MockSamlPdp;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.saml.SecmgrCredential;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.opensaml.common.xml.SAMLConstants;

/**
 * Tests for the {@link SamlModule} class.
 */
public class SamlModuleTest extends SecurityManagerTestCase {

  private static final String ENTITY_ID_1 = "http://example.com/saml-pdp-1";
  private static final String ENTITY_ID_2 = "http://example.com/saml-pdp-2";

  private static final String URL1 = "http://example.com/doc1";
  private static final String URL2 = "http://example.com/doc2";
  private static final String URL3 = "http://example.com/doc3";

  private static final String[] ALL_URLS = new String[] { URL1, URL2, URL3 };

  private static final String MECH1_NAME = "mech1";
  private static final String MECH2_NAME = "mech2";

  private final SamlModule module;
  private final AuthnMechanism mech1;
  private final AuthnMechanism mech2;
  private final SecurityManagerConfig config;
  private final FlexAuthzRule rule1;
  private final FlexAuthzRule rule2;
  private final AuthnSessionManager sessionManager;
  private AuthnSession session;

  public SamlModuleTest() {
    module = ConfigSingleton.getInstance(SamlModule.class);
    mech1 = AuthnMechSaml.make(MECH1_NAME, ENTITY_ID_1);
    mech2 = AuthnMechSaml.make(MECH2_NAME, ENTITY_ID_2);
    config = makeConfig(
        ImmutableList.of(
            CredentialGroup.builder("CG1", "CG1 display", true, true, false)
            .addMechanism(mech1)
            .build(),
            CredentialGroup.builder("CG2", "CG2 display", true, true, false)
            .addMechanism(mech2)
            .build()));
    rule1 = new FlexAuthzRule(MECH1_NAME, AuthzMechanism.SAML,
        ImmutableMap.of(
            ParamName.SAML_ENTITY_ID, ENTITY_ID_1,
            ParamName.SAML_USE_BATCHED_REQUESTS, Boolean.FALSE.toString()),
        MECH1_NAME, FlexAuthzRule.NO_TIME_LIMIT);
    rule2 = new FlexAuthzRule(MECH2_NAME, AuthzMechanism.SAML,
        ImmutableMap.of(
            ParamName.SAML_ENTITY_ID, ENTITY_ID_2,
            ParamName.SAML_USE_BATCHED_REQUESTS, Boolean.TRUE.toString()),
        MECH2_NAME, FlexAuthzRule.NO_TIME_LIMIT);
    sessionManager = ConfigSingleton.getInstance(AuthnSessionManager.class);
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    session = AuthnSession.newInstance(config);
  }

  public void testAuthzWithPasswordSuccess() throws Exception {
    // GroupMemberships.make will complain if we provide empty group, so even here the
    // group info is not used, we still provide one group. Same for other Password tests.
    List<Group> groups = Arrays.asList(Group.make("group1", "CG1", "test"));
    SecmgrCredential user = makeVerifiedUser(mech1, "USER1", "CG1", "test", "p@ssw0rd", groups);

    Map<String, SecmgrCredential> credMap = ImmutableMap.<String, SecmgrCredential>builder()
        .put(user.getName(), user)
        .build();

    String userFullname = user.getDomain() + "\\" + user.getName();
    Multimap<String, String> authorizationMap = ImmutableMultimap.<String, String>builder()
        .put(userFullname, URL1)
        .put(userFullname, URL2)
        .build();
    Map<String, String> usernamePasswordMap = ImmutableMap.<String, String>builder()
        .put(userFullname, user.getPassword())
        .build();
    AuthorizeWithCredential method = new AuthorizeByThirdParty(usernamePasswordMap,
        authorizationMap);

    MockSamlPdp samlPdp = new MockSamlPdp(SamlSharedData.make(ENTITY_ID_1,
        SamlSharedData.Role.AUTHZ_SERVER, null), credMap, method, ConfigSingleton.getInstance(AuthnSessionManager.class));
    setSamlPdp(samlPdp, ENTITY_ID_1);

    AuthzResult responses = tryResources(mech1, rule1, URL1, URL2, URL3);
    AuthzResult.Builder goldenResponsesBuilder = AuthzResult.builder(
        Arrays.asList(URL1, URL2, URL3));
    AuthzResult goldenResponses = goldenResponsesBuilder
        .put(URL1, AuthzStatus.PERMIT)
        .put(URL2, AuthzStatus.PERMIT)
        .put(URL3, AuthzStatus.DENY)
        .build();
    assertEquals(goldenResponses, responses);
  }

  public void testBatchV1AuthzWithPasswordSuccess() throws Exception {
    List<Group> groups = Arrays.asList(Group.make("group1", "CG2", "test"));
    SecmgrCredential user = makeVerifiedUser(mech2, "USER1", "CG2", "test", "p@ssw0rd", groups);

    Map<String, SecmgrCredential> credMap = ImmutableMap.<String, SecmgrCredential>builder()
        .put(user.getName(), user)
        .build();

    String userFullname = user.getDomain() + "\\" + user.getName();
    Multimap<String, String> authorizationMap = ImmutableMultimap.<String, String>builder()
        .put(userFullname, URL1)
        .put(userFullname, URL2)
        .build();
    Map<String, String> usernamePasswordMap = ImmutableMap.<String, String>builder()
        .put(userFullname, user.getPassword())
        .build();
    AuthorizeWithCredential method = new AuthorizeByThirdParty(usernamePasswordMap,
        authorizationMap);

    MockSamlPdp samlPdp = new MockSamlPdp(SamlSharedData.make(ENTITY_ID_2,
        SamlSharedData.Role.AUTHZ_SERVER, null), credMap, method, ConfigSingleton.getInstance(AuthnSessionManager.class));
    setSamlPdp(samlPdp, ENTITY_ID_2);

    AuthzResult responses = tryResources(mech2, rule2, URL1, URL2, URL3);
    AuthzResult.Builder goldenResponsesBuilder = AuthzResult.builder(
        Arrays.asList(URL1, URL2, URL3));
    AuthzResult goldenResponses = goldenResponsesBuilder
        .put(URL1, AuthzStatus.PERMIT)
        .put(URL2, AuthzStatus.PERMIT)
        // Whether we should put INDETERMINATE or DENY is not important here
        // because it just depends on the implementation of PDP. We just need
        // to make sure the PDP gets the credential it needs to make the decision.
        .put(URL3, AuthzStatus.DENY)
        .build();
    assertEquals(goldenResponses, responses);
  }

  public void testAuthzWithWrongPasswordAllDeny() throws Exception {
    List<Group> groups = Arrays.asList(Group.make("group1", "CG1", "test"));
    SecmgrCredential user = makeVerifiedUser(mech1, "USER1", "CG1", "test", "p@ssw0rd", groups);

    Map<String, SecmgrCredential> credMap = ImmutableMap.<String, SecmgrCredential>builder()
        .put(user.getName(), user)
        .build();

    String userFullname = user.getDomain() + "\\" + user.getName();
    Multimap<String, String> authorizationMap = ImmutableMultimap.<String, String>builder()
        .put(userFullname, URL1)
        .put(userFullname, URL2)
        .build();
    Map<String, String> usernamePasswordMap = ImmutableMap.<String, String>builder()
        .put(userFullname, "correct_password")
        .build();
    AuthorizeWithCredential method = new AuthorizeByThirdParty(usernamePasswordMap,
        authorizationMap);

    MockSamlPdp samlPdp = new MockSamlPdp(SamlSharedData.make(ENTITY_ID_1,
        SamlSharedData.Role.AUTHZ_SERVER, null), credMap, method, ConfigSingleton.getInstance(AuthnSessionManager.class));
    setSamlPdp(samlPdp, ENTITY_ID_1);

    AuthzResult responses = tryResources(mech1, rule1, URL1, URL2);
    AuthzResult.Builder goldenResponsesBuilder = AuthzResult.builder(Arrays.asList(URL1, URL2));
    AuthzResult goldenResponses = goldenResponsesBuilder
        .put(URL1, AuthzStatus.DENY)
        .put(URL2, AuthzStatus.DENY)
        .build();
    assertEquals(goldenResponses, responses);
  }

  public void testBatchV1AuthzWithWrongPasswordAllDeny() throws Exception {
    List<Group> groups = Arrays.asList(Group.make("group1", "CG2", "test"));
    SecmgrCredential user = makeVerifiedUser(mech2, "USER1", "CG2", "test", "p@ssw0rd", groups);

    Map<String, SecmgrCredential> credMap = ImmutableMap.<String, SecmgrCredential>builder()
        .put(user.getName(), user)
        .build();

    String userFullname = user.getDomain() + "\\" + user.getName();
    Multimap<String, String> authorizationMap = ImmutableMultimap.<String, String>builder()
        .put(userFullname, URL1)
        .put(userFullname, URL2)
        .build();
    Map<String, String> usernamePasswordMap = ImmutableMap.<String, String>builder()
        .put(userFullname, "correct_password")
        .build();
    AuthorizeWithCredential method = new AuthorizeByThirdParty(usernamePasswordMap,
        authorizationMap);

    MockSamlPdp samlPdp = new MockSamlPdp(SamlSharedData.make(ENTITY_ID_2,
        SamlSharedData.Role.AUTHZ_SERVER, null), credMap, method, ConfigSingleton.getInstance(AuthnSessionManager.class));
    setSamlPdp(samlPdp, ENTITY_ID_2);

    AuthzResult responses = tryResources(mech2, rule2, URL1, URL2);
    AuthzResult.Builder goldenResponsesBuilder = AuthzResult.builder(Arrays.asList(URL1, URL2));
    AuthzResult goldenResponses = goldenResponsesBuilder
        .put(URL1, AuthzStatus.DENY)
        .put(URL2, AuthzStatus.DENY)
        .build();
    assertEquals(goldenResponses, responses);
  }

  public void testAuthzWithAcl() throws Exception {
    List<Group> groups = Arrays.asList(
        Group.make("group1", "CG1", "test"),
        Group.make("group2", "CG1", "test"));
    SecmgrCredential user = makeVerifiedUser(mech1, "USER1", "CG1", "test", "p@ssw0rd", groups);

    Map<String, SecmgrCredential> credMap = ImmutableMap.<String, SecmgrCredential>builder()
        .put(user.getName(), user)
        .build();

    AuthorizeByAcl.Acl.Builder url1AclBuilder = new AuthorizeByAcl.Acl.Builder()
        .setPermitGroups(Arrays.asList(Group.make("group1", "CG1", "test")));
    AuthorizeByAcl.Acl.Builder url2AclBuilder = new AuthorizeByAcl.Acl.Builder()
        .setPermitGroups(Arrays.asList(Group.make("group2", "CG1", "test")));
    AuthorizeByAcl.Acl.Builder url3AclBuilder = new AuthorizeByAcl.Acl.Builder()
        .setPermitGroups(Arrays.asList(Group.make("group3", "CG1", "test")));
    Map<String, AuthorizeByAcl.Acl> aclMap = ImmutableMap.<String, AuthorizeByAcl.Acl>builder()
        .put(URL1, url1AclBuilder.build())
        .put(URL2, url2AclBuilder.build())
        .put(URL3, url3AclBuilder.build())
        .build();
    AuthorizeWithCredential method = new AuthorizeByAcl(aclMap);

    MockSamlPdp samlPdp = new MockSamlPdp(SamlSharedData.make(ENTITY_ID_1,
        SamlSharedData.Role.AUTHZ_SERVER, null), credMap, method, ConfigSingleton.getInstance(AuthnSessionManager.class));
    setSamlPdp(samlPdp, ENTITY_ID_1);

    AuthzResult responses = tryResources(mech1, rule1, URL1, URL2, URL3);
    AuthzResult.Builder goldenResponsesBuilder = AuthzResult.builder(
        Arrays.asList(URL1, URL2, URL3));
    AuthzResult goldenResponses = goldenResponsesBuilder
        .put(URL1, AuthzStatus.PERMIT)
        .put(URL2, AuthzStatus.PERMIT)
        .put(URL3, AuthzStatus.DENY)
        .build();
    assertEquals(goldenResponses, responses);
  }

  public void testBatchV1AuthzWithAcl() throws Exception {
    List<Group> groups = Arrays.asList(
        Group.make("group1", "CG2", "test"),
        Group.make("group2", "CG2", "test"));
    SecmgrCredential user = makeVerifiedUser(mech2, "USER1", "CG2", "test", "p@ssw0rd", groups);

    Map<String, SecmgrCredential> credMap = ImmutableMap.<String, SecmgrCredential>builder()
        .put(user.getName(), user)
        .build();

    AuthorizeByAcl.Acl.Builder url1AclBuilder = new AuthorizeByAcl.Acl.Builder()
        .setPermitGroups(Arrays.asList(Group.make("group1", "CG2", "test")));
    AuthorizeByAcl.Acl.Builder url2AclBuilder = new AuthorizeByAcl.Acl.Builder()
        .setPermitGroups(Arrays.asList(Group.make("group2", "CG2", "test")));
    AuthorizeByAcl.Acl.Builder url3AclBuilder = new AuthorizeByAcl.Acl.Builder()
        .setPermitGroups(Arrays.asList(Group.make("group3", "CG2", "test")));
    Map<String, AuthorizeByAcl.Acl> aclMap = ImmutableMap.<String, AuthorizeByAcl.Acl>builder()
        .put(URL1, url1AclBuilder.build())
        .put(URL2, url2AclBuilder.build())
        .put(URL3, url3AclBuilder.build())
        .build();
    AuthorizeWithCredential method = new AuthorizeByAcl(aclMap);

    MockSamlPdp samlPdp = new MockSamlPdp(SamlSharedData.make(ENTITY_ID_2,
        SamlSharedData.Role.AUTHZ_SERVER, null), credMap, method, ConfigSingleton.getInstance(AuthnSessionManager.class));
    setSamlPdp(samlPdp, ENTITY_ID_2);

    AuthzResult responses = tryResources(mech2, rule2, URL1, URL2, URL3);
    AuthzResult.Builder goldenResponsesBuilder = AuthzResult.builder(
        Arrays.asList(URL1, URL2, URL3));
    AuthzResult goldenResponses = goldenResponsesBuilder
        .put(URL1, AuthzStatus.PERMIT)
        .put(URL2, AuthzStatus.PERMIT)
        .put(URL3, AuthzStatus.DENY)
        .build();
    assertEquals(goldenResponses, responses);
  }

  private SecmgrCredential makeVerifiedUser(AuthnMechanism verifiedByMech, String name,
      String namespace, String domain, String password, List<Group> groups) {
    SecmgrCredential cred = OpenSamlUtil.makeSecmgrCredential(name, namespace, domain,
        password, OpenSamlUtil.makeSamlGroupsFromIdentityGroups(groups));

    session.addVerification(verifiedByMech.getAuthority(),
        Verification.verified(Verification.NEVER_EXPIRES,
            AuthnPrincipal.make(cred.getName(), cred.getNamespace(), cred.getDomain()),
            CredPassword.make(cred.getPassword()),
            GroupMemberships.make(groups)));
    sessionManager.saveSession(session);
    return cred;
  }

  private void setSamlPdp(MockSamlPdp samlPdp, String entityId) throws Exception {
    Metadata metadata = Metadata.getInstanceForTest();
    MockHttpTransport transport = ConfigSingleton.getInstance(MockHttpTransport.class);
    transport.registerServlet(
        metadata.getEntity(entityId).getPDPDescriptor(SAMLConstants.SAML20P_NS)
        .getAuthzServices().get(0).getLocation(), samlPdp);
    HttpClientUtil.setHttpClient(new MockHttpClient(transport));
  }

  private static final Logger logger = Logger.getLogger(SamlModuleTest.class.getName());
  private AuthzResult tryResources(AuthnMechanism mech, FlexAuthzRule rule, String... resourceUrls)
      throws IOException {
    SessionView view = session.getView(mech);
    try {
      AuthzResult responses = module.authorize(
          Resource.urlsToResourcesNoAcls(ImmutableList.copyOf(resourceUrls)), view, rule);
      assertNotNull(responses);
      assertEquals(resourceUrls.length, responses.size());
      return responses;
    } catch (IOException e) {
      logger.log(Level.SEVERE, e.getMessage(), e);
      throw e;
    }
  }
}
