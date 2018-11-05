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

package com.google.enterprise.secmgr.config;

import static com.google.enterprise.secmgr.config.ConfigTestUtil.jsonArray;
import static com.google.enterprise.secmgr.config.ConfigTestUtil.jsonBinding;
import static com.google.enterprise.secmgr.config.ConfigTestUtil.jsonObject;
import static com.google.enterprise.secmgr.config.ConfigTestUtil.jsonQuote;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.truth.Truth;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;

/**
 * Unit test for JsonConfig.
 */
public class JsonConfigTest extends SecurityManagerTestCase {

  private static final String GROUPS_NAME_RANDOMNUMBER = "12345";
  private JsonConfig codec;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    codec = ConfigSingleton.getInstance(JsonConfig.class);
  }

  /**
   * Test that an empty config file throws ConfigException.
   */
  public void testEmptyConfigFile() throws IOException {
    try {
      codec.readConfig("");
    } catch (ConfigException e) {
      return;
    }
    fail();
  }

  public void testCurrentConfig() throws Exception{
    SecurityManagerConfig expected
        = makeConfig(
            Lists.newArrayList(
                CredentialGroupTest.makeCg1(),
                CredentialGroupTest.makeCg2()));

    AuthnMechGroups.setGroupsNameSuffix(GROUPS_NAME_RANDOMNUMBER);
    SecurityManagerConfig actual = codec.readConfig(configToString(expected));
    assertEquals(expected, actual);

    // Check that encoding and decoding the config results in the same config.
    AuthnMechGroups.setGroupsNameSuffix(GROUPS_NAME_RANDOMNUMBER);
    actual = codec.readConfig(codec.configToString(expected));
    assertConfigsEqual(actual, expected);
  }

  private String configToString(SecurityManagerConfig config) {
    return jsonObject(
        jsonBinding("version", Integer.toString(config.getVersion())),
        jsonBinding("CGs",
            jsonArray(
                Iterables.transform(config.getCredentialGroups(),
                    new Function<CredentialGroup, String>() {
                      @Override
                      public String apply(CredentialGroup cg) {
                        return CredentialGroupTest.makeCgString(cg);
                      }
                    }))),
        jsonBinding("params", paramsToString(config.getParams())),
        jsonBinding("flexAuthz", flexAuthzToString(config.getFlexAuthorizer())));
  }

  private String paramsToString(ConfigParams params) {
    ImmutableList.Builder<String> builder = ImmutableList.builder();
    for (ParamName key : ConfigParams.keySet()) {
      builder.add(jsonBinding(key.toString(), paramValueToString(key, params)));
    }
    return jsonObject(builder.build().toArray(new String[0]));
  }

  private String paramValueToString(ParamName key, ConfigParams params) {
    Object value = params.get(key);
    if (value instanceof String) {
      return jsonQuote((String) value);
    }
    return value.toString();
  }

  private String flexAuthzToString(FlexAuthorizer flexAuthorizer) {
    List<FlexAuthzRoutingTableEntry> routingTable = flexAuthorizer.getAllRoutingTable();
    String routingJson = jsonBinding("entries",
        jsonArray(
            Iterables.transform(routingTable,
                new Function<FlexAuthzRoutingTableEntry, String>() {
                    @Override
                    public String apply(FlexAuthzRoutingTableEntry entry) {
                      return jsonObject(
                          jsonBinding("urlPattern", jsonQuote(entry.getUrlPattern())),
                          jsonBinding("authzRule", flexAuthzRuleToString(entry.getAuthzRule())),
                          jsonBinding("uniqueRowId",
                                      jsonQuote(entry.getUniqueRowId().toString())));
                    }
                })));
    return jsonObject(routingJson);
  }

  private String flexAuthzRuleToString(FlexAuthzRule rule) {
    List<String> jObjects = Lists.newArrayList();
    jObjects.add(jsonBinding("authnId", jsonQuote(rule.getAuthnId())));
    jObjects.add(jsonBinding("authzMechType",
                             jsonQuote(rule.getAuthzMechType().toString())));
    Map<FlexAuthzRule.ParamName, String> mechSpecificParams =
        rule.getMechSpecificParams();
    for (FlexAuthzRule.ParamName paramName : mechSpecificParams.keySet()) {
      jObjects.add(jsonBinding(convertParamNameToJsonKey(paramName),
                               jsonQuote(mechSpecificParams.get(paramName))));
    }
    jObjects.add(jsonBinding("displayName", jsonQuote(rule.getRowDisplayName())));
    jObjects.add(jsonBinding("timeout", Integer.toString(rule.getTimeout())));
    return jsonObject(jObjects);
  }

  /**
   * Converts the FlexAuthzRule mechanism specific param name to its
   * corresponding json key as defined in FlexAuthzRule.localProxy.
   */
  private String convertParamNameToJsonKey(FlexAuthzRule.ParamName paramName) {
    switch (paramName) {
      case CONNECTOR_NAME:
        return "connectorName";
      case SAML_ENTITY_ID:
        return "samlEntityId";
      case SAML_USE_BATCHED_REQUESTS:
        return "samlUseBatchedRequests";
      default:
        return "";
    }
  }

  /**
   * Test upgrading an old configuration file.  The file used here is the
   * configuration that was in ABCDE when this was written.
   */
  public void testOldConfig() throws Exception {
    File configFile = FileUtil.getContextFile("AuthSitesV0.json");
    AuthnMechGroups.setGroupsNameSuffix(GROUPS_NAME_RANDOMNUMBER);
    SecurityManagerConfig config = codec.readConfig(configFile);
    assertConfigsEqual(config, makeV0Config());
  }

  private SecurityManagerConfig makeV0Config() {
    return SecurityManagerConfig.make(
        Lists.newArrayList(
            CredentialGroup.builder("Default", null, true, false, false)
            .addMechanism(AuthnMechForm.make(null,
                    "http://ent-test-oblix1.corp.google.com/Site1/docs/"))
            .addMechanism(AuthnMechForm.make(null, "http://ent-test-siteminder1.corp.google.com/"))
            .addMechanism(AuthnMechGroups.make("Default_groups_" + GROUPS_NAME_RANDOMNUMBER))
            .build(),
            CredentialGroup.builder("lab", "beautiful lab", false, false, true)
            .addMechanism(AuthnMechForm.make(null,
                    "http://forms-auth-test.corp.google.com/content1"))
            .addMechanism(AuthnMechBasic.make(null,
                    "http://http-auth-test.corp.google.com/"))
            .addMechanism(AuthnMechGroups.make("lab_groups_" + GROUPS_NAME_RANDOMNUMBER))
            .build()),
        ConfigParams.makeDefault(),
        FlexAuthorizerImpl.makeDefault());
  }

  /**
   * This tests loading an old config containing a credential group with no
   * configured domains.  This config was used by QA in testing and resulted in
   * a null pointer exception.
   */
  public void testOldConfigWithNoDomains() throws Exception {
    File configFile = FileUtil.getContextFile("AuthSitesV0b.json");
    AuthnMechGroups.setGroupsNameSuffix(GROUPS_NAME_RANDOMNUMBER);
    SecurityManagerConfig config = codec.readConfig(configFile);
    assertConfigsEqual(config, makeV0bConfig());
  }

  private SecurityManagerConfig makeV0bConfig() {
    return SecurityManagerConfig.make(
        Lists.newArrayList(
            CredentialGroup.builder("Default", null, true, false, false)
            .addMechanism(AuthnMechBasic.make(null,
                    "http://afcontent-testbed.hot.corp.google.com/sslsecure/test1/"))
            .addMechanism(AuthnMechGroups.make("Default_groups_" + GROUPS_NAME_RANDOMNUMBER))
            .build(),
            CredentialGroup.builder("Form", null, false, false, false)
            .addMechanism(AuthnMechForm.make(null,
                    "http://ent-test-siteminder1.corp.google.com/test1/"))
            .addMechanism(AuthnMechGroups.make("Form_groups_" + GROUPS_NAME_RANDOMNUMBER))
            .build(),
            CredentialGroup.builder("Basic", null, false, false, false)
            .addMechanism(AuthnMechGroups.make("Basic_groups_" + GROUPS_NAME_RANDOMNUMBER))
            .build()),
        ConfigParams.makeDefault(),
        FlexAuthorizerImpl.makeDefault());
  }

  /**
   * Test upgrading a V1 configuration file.
   */
  public void testV1Config() throws Exception {
    File configFile = FileUtil.getContextFile("AuthSitesV1.json");
    AuthnMechGroups.setGroupsNameSuffix(GROUPS_NAME_RANDOMNUMBER);
    assertConfigsEqual(codec.readConfig(configFile), makeV1Config());
  }

  private SecurityManagerConfig makeV1Config() {
    return SecurityManagerConfig.make(
        Lists.newArrayList(
            CredentialGroup.builder("Default", null, true, false, false)
            .addMechanism(AuthnMechForm.make(null, "http://localhost:47998/content1"))
            .addMechanism(AuthnMechGroups.make("Default_groups_" + GROUPS_NAME_RANDOMNUMBER))
            .build()),
        ConfigParams.makeDefault(),
        FlexAuthorizerImpl.makeDefault());
  }

  /**
   * Test reading the version 4 configuration file.
   */
  public void testV4Config() throws Exception {
    File configFile = FileUtil.getContextFile("AuthSitesV4.json");
    AuthnMechGroups.setGroupsNameSuffix(GROUPS_NAME_RANDOMNUMBER);
    SecurityManagerConfig config = codec.readConfig(configFile);
    assertConfigsEqual(config, makeV4Config());
  }

  private SecurityManagerConfig makeV4Config() {
    return SecurityManagerConfig.make(
        Lists.newArrayList(
            CredentialGroup.builder("ADG1", "ADG1 display", false, false, false)
            .addMechanism(AuthnMechForm.make(null, "http://form1.example.com/mockcontentserver1"))
            .addMechanism(AuthnMechGroups.make("ADG1_groups_" + GROUPS_NAME_RANDOMNUMBER))
            .build()),
        ConfigParams.builder()
            .put(ParamName.ACL_GROUPS_FILENAME, "acl_groups.enterprise")
            .put(ParamName.ACL_URLS_FILENAME, "acl_urls.enterprise")
            .put(ParamName.DENY_RULES_FILENAME, "deny_rules.enterprise")
            .put(ParamName.GLOBAL_SINGLE_REQUEST_TIMEOUT, 2.5f)
            .put(ParamName.GLOBAL_BATCH_REQUEST_TIMEOUT, 5.0f)
            .put(ParamName.CERTIFICATE_AUTHORITIES_FILENAME, "cacerts.jks")
            .put(ParamName.SAML_METADATA_FILENAME, "saml-metadata.xml")
            .put(ParamName.SERVER_CERTIFICATE_FILENAME, "server.jks")
            .put(ParamName.SIGNING_CERTIFICATE_FILENAME, "saml-server-test.crt")
            .put(ParamName.SIGNING_KEY_FILENAME, "saml-server-test.key")
            .put(ParamName.STUNNEL_PORT, 7843)
            .build(),
        FlexAuthorizerImpl.makeDefault());
  }

  /**
   * Test reading the version 7 configuration file, and its upgrade to a newer version.
   */
  public void testV7Config() throws Exception {
    File configFile = FileUtil.getContextFile("AuthSitesV7.json");
    AuthnMechGroups.setGroupsNameSuffix(GROUPS_NAME_RANDOMNUMBER);
    SecurityManagerConfig config = codec.readConfig(configFile);
    // One of important changes between V7 and V8 was removal of file system rules.
    // This needs to be validated in the test.
    assertConfigsEqual(config, makeV7Config());
  }

  private SecurityManagerConfig makeV7Config() {
    return SecurityManagerConfig.make(
        Lists.newArrayList(
            CredentialGroup.builder("ADG1", "ADG1 display", false, false, false)
                .addMechanism(AuthnMechForm.make("form-1",
                                             "http://form1.example.com/mockcontentserver1",
                                             20,
                                             AuthnMechForm.getDefaultTrustDuration()))
                .addMechanism(AuthnMechSaml.make("saml-1", "entity1", 60))
                .build()),
        ConfigParams.builder()
            .put(ParamName.ACL_GROUPS_FILENAME, "acl_groupsv7.enterprise")
            .build(),
        FlexAuthorizerImpl.makeDefault());
  }

  /**
   * Test reading the version 6 configuration file.
   */
  public void testV6Config() throws Exception {
    File configFile = FileUtil.getContextFile("AuthSitesV6.json");
    AuthnMechGroups.setGroupsNameSuffix(GROUPS_NAME_RANDOMNUMBER);
    SecurityManagerConfig config = codec.readConfig(configFile);
    assertConfigsEqual(config, makeV6Config());
  }

  public void testV6ConfigWithFlexAuthz() throws IOException, ConfigException {
    File configFile = FileUtil.getContextFile("AuthSitesV6FlexAuthz.json");
    AuthnMechGroups.setGroupsNameSuffix(GROUPS_NAME_RANDOMNUMBER);
    SecurityManagerConfig config = codec.readConfig(configFile);
    FlexAuthorizer flexAuthorizer = config.getFlexAuthorizer();
    // THe AuthSitesV6FlexAuthz.json contains 4 rules. In config versions older than 8 there
    // was an additional rule added for the file system. However, since version 8 this rule is
    // removed, as the config gets upgraded.
    for (FlexAuthzRule rule : flexAuthorizer.getAllRulesTable()) {
      Truth.assertThat(rule).isNotEqualTo(AuthzMechanism.FILE_SYSTEM);
    }
  }

  private SecurityManagerConfig makeV6Config() {
    return SecurityManagerConfig.make(
        Lists.newArrayList(
            CredentialGroup.builder("ADG1", "ADG1 display", false, false, false)
            .addMechanism(AuthnMechForm.make("form-1",
                                             "http://form1.example.com/mockcontentserver1",
                                             20,
                                             AuthnMechForm.getDefaultTrustDuration()))
            .addMechanism(AuthnMechBasic.make("basic-1",
                                             "http://basic1.example.com/mockcontentserver1",
                                             30,
                                             AuthnMechBasic.getDefaultTrustDuration()))
            .addMechanism(AuthnMechNtlm.make("ntlm-1",
                                             "http://ntlm1.example.com/mockcontentserver1",
                                             40,
                                             AuthnMechNtlm.getDefaultTrustDuration()))
            .addMechanism(AuthnMechLdap.make("ldap-1",
                                             "ldap://ldap1.example.com/",
                                             "cn=test", //bind dn
                                             "pwd",
                                             "dn=testdomain", // search base
                                             "", // user filter
                                             "", // group filter
                                             "CN", // group format
                                             0, // ssl support
                                             0, // auth methods
                                             true, // enable authn
                                             true, // enable group lookup
                                             true, // implicate everyone
                                             50, //timeout
                                             AuthnMechLdap.getDefaultTrustDuration()))
            .addMechanism(AuthnMechSaml.make("saml-1", "entity1", 60))
            .addMechanism(AuthnMechConnector.make("conn-1",
                                                  "connector1",
                                                  false,
                                                  70,
                                                  AuthnMechConnector.getDefaultTrustDuration()))
            .addMechanism(AuthnMechGroups.make("ADG1_groups_" + GROUPS_NAME_RANDOMNUMBER))
            .build()),
        ConfigParams.builder()
            .put(ParamName.ACL_GROUPS_FILENAME, "acl_groups.enterprise")
            .put(ParamName.ACL_URLS_FILENAME, "acl_urls.enterprise")
            .put(ParamName.AUTHZ_CONFIG_FILENAME, "../../../../conf/FlexAuthz.xml")
            .put(ParamName.DENY_RULES_FILENAME, "deny_rules.enterprise")
            .put(ParamName.GLOBAL_SINGLE_REQUEST_TIMEOUT, 2.5f)
            .put(ParamName.GLOBAL_BATCH_REQUEST_TIMEOUT, 5.0f)
            .put(ParamName.CERTIFICATE_AUTHORITIES_FILENAME, "cacerts.jks")
            .put(ParamName.SAML_METADATA_FILENAME, "saml-metadata.xml")
            .put(ParamName.SERVER_CERTIFICATE_FILENAME, "server.jks")
            .put(ParamName.SIGNING_CERTIFICATE_FILENAME, "saml-server-test.crt")
            .put(ParamName.SIGNING_KEY_FILENAME, "saml-server-test.key")
            .put(ParamName.STUNNEL_PORT, 7843)
            .build(),
        FlexAuthorizerImpl.makeDefault());
  }

  public void testConfigWithTimeoutsSwapped() throws IOException, ConfigException {
    SecurityManagerConfig config =
        codec.readConfig(configToString(makeConfigWithTimeoutsSwapped()));
    assertEquals(ParamName.GLOBAL_SINGLE_REQUEST_TIMEOUT.getDefaultValue(),
        config.getParams().get(ParamName.GLOBAL_SINGLE_REQUEST_TIMEOUT, Float.class));
    assertEquals(ParamName.GLOBAL_BATCH_REQUEST_TIMEOUT.getDefaultValue(),
        config.getParams().get(ParamName.GLOBAL_BATCH_REQUEST_TIMEOUT, Float.class));
  }

  private SecurityManagerConfig makeConfigWithTimeoutsSwapped() {
    return SecurityManagerConfig.make(
        Lists.newArrayList(
            CredentialGroup.builder("ADG1", "ADG1 display", false, false, false)
            .build()),
        ConfigParams.builder()
            .put(ParamName.GLOBAL_SINGLE_REQUEST_TIMEOUT, 5.0f)
            .put(ParamName.GLOBAL_BATCH_REQUEST_TIMEOUT, 2.5f)
            .build(),
        FlexAuthorizerImpl.makeDefault());
  }

  private void assertConfigsEqual(SecurityManagerConfig actual, SecurityManagerConfig expected)
      throws Exception {
    final JSONObject actualJson = new JSONObject(actual.toString());
    final JSONObject expectedJson = new JSONObject(expected.toString());
    Truth.assertThat(actual.getVersion()).isEqualTo(expected.getVersion());
    JsonAssert.assertEquals(expectedJson.getJSONObject("params"),
        actualJson.getJSONObject("params"));
    Truth.assertThat(actual.getFlexAuthorizer().getAllRulesTable()).containsExactlyElementsIn(
        expected.getFlexAuthorizer().getAllRulesTable());
    Truth.assertThat(actual.getFlexAuthorizer().getAllRoutingTable()).containsExactlyElementsIn(
        expected.getFlexAuthorizer().getAllRoutingTable());
    Truth.assertThat(actual.getCredentialGroups()).containsExactlyElementsIn(
        expected.getCredentialGroups());
  }
}
