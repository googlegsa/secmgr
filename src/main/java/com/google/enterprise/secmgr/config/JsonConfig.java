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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.json.ProxyTypeAdapter;
import com.google.enterprise.secmgr.json.TypeProxy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.annotations.SerializedName;
import com.google.inject.Singleton;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * JsonConfig is the class that reads the security manager's authn sites
 * configuration from a JSON file.
 */
@Immutable
@Singleton
public class JsonConfig extends ConfigCodec {
  private static final Logger logger = Logger.getLogger(JsonConfig.class.getName());

  @Inject
  private JsonConfig() {
  }

  @VisibleForTesting
  public static JsonConfig make() {
    return new JsonConfig();
  }

  @Override
  protected void writeConfigInternal(SecurityManagerConfig config, Writer writer) {
    ConfigSingleton.getGson().toJson(config, writer);
  }

  @Override
  protected SecurityManagerConfig readConfigInternal(Reader reader)
      throws IOException, ConfigException {
    JsonElement je = null;
    // Get valid JSON element or log warning and return default config.
    try {
      je = (new JsonParser()).parse(reader);
    } catch (JsonParseException e) {
      Throwable cause = e.getCause();
      if (cause instanceof IOException) {
        throw (IOException) cause;
      }
      throw new ConfigException(e);
    }

    SecurityManagerConfig config;
    try {
      config = ConfigSingleton.getGson().fromJson(je, SecurityManagerConfig.class);
    } catch (Exception e) {
      // Replicating catch-all workaround from an internal G-patch
      logger.info("Exception parsing JSON config element: " + e.getMessage());
      return tryPreVersionNumberCodec(je);
    }

    if (config == null) {
      return tryPreVersionNumberCodec(je);
    }

    try {
      config = ensureCorrectParamValues(config);
      return ensureIsCurrentVersion(config, je);
    } catch (JsonParseException e) {
      logger.info("Exception parsing JSON config element: " + e.getMessage());
      return tryPreVersionNumberCodec(je);
    }
  }

  /* Tries to decode using original codec.  Returns default config on failure. */
  private static SecurityManagerConfig tryPreVersionNumberCodec(JsonElement je)
      throws ConfigException {
    // First check to see if there's a version number; if so, this isn't a
    // pre-version config.
    if (je.isJsonObject() && je.getAsJsonObject().has("version")) {
      throw new ConfigException("Unable to parse JSON config");
    }
    logger.info("Trying original codec to parse configuration");
    SecurityManagerConfig earlyConfig;
    try {
      earlyConfig = V0_SMC_GSON.fromJson(je, SecurityManagerConfig.class);
    } catch (JsonParseException e) {
      throw new ConfigException("Unable to parse JSON config: ", e);
    }
    if (earlyConfig == null) {
      throw new ConfigException("Unable to parse JSON config");
    }
    return ensureIsCurrentVersion(earlyConfig, je);
  }

  @SuppressWarnings("fallthrough")
  private static SecurityManagerConfig ensureIsCurrentVersion(SecurityManagerConfig config,
      JsonElement je)
      throws ConfigException {
    switch (config.getVersion()) {
      case 1:
        config = convertV1ConfigToV2(config);
        logger.info("Converted version 1 to version " + config.getVersion());
        // Fallthrough.
      case 2:
        config = convertV2ConfigToV3(config);
        logger.info("Converted version 2 to version " + config.getVersion());
        // Fallthrough.
      case 3:
        config = convertV3ConfigToV4(config, je);
        logger.info("Converted version 3 to version " + config.getVersion());
        // Fallthrough.
      case 4:
        config = convertV4ConfigToV5(config);
        logger.info("Converted version 4 to version " + config.getVersion());
        // Fallthrough.
      case 5:
        config = convertV5ConfigToV6(config);
        logger.info("Converted version 5 to version " + config.getVersion());
        // Fallthrough.
      case 6:
        config = convertV6ConfigToV7(config);
        logger.info("Converted version 6 to version " + config.getVersion());
        // Fallthrough.
      case 7:
        config = convertV7ConfigToV8(config);
        logger.info("Converted version 7 to version " + config.getVersion());
        return config;
      case 8:
        if (config.getVersion() != SecurityManagerConfig.CURRENT_VERSION) {
          throw new ConfigException(
              "Wrong config version at end of parsing: " + config.getVersion()
              + " expected " + SecurityManagerConfig.CURRENT_VERSION);
        }
        return config;
      default:
        throw new ConfigException("Unknown config version: " + config.getVersion());
    }
  }

  /**
   *  Placeholder method to verify the param values read from the config file are correct. At the
   *  moment, it only checks for the case when single request timeout value is greater than the
   *  batch request timeout values. It can be extended in future to add other sanity checks.
   */
  private static SecurityManagerConfig ensureCorrectParamValues(SecurityManagerConfig config) {
    ConfigParams params = config.getParams();
    float singleReqTimeout =
        params.get(ParamName.GLOBAL_SINGLE_REQUEST_TIMEOUT, Float.class).floatValue();
    float batchReqTimeout =
        params.get(ParamName.GLOBAL_BATCH_REQUEST_TIMEOUT, Float.class).floatValue();
    if (singleReqTimeout > batchReqTimeout) {
      logger.info("The value of SINGLE_REQUEST_TIMEOUT is greater than BATCH_REQUEST_TIMEOUT in "
          + "the config file: setting default values.");
      ConfigParams.Builder paramBuilder = ConfigParams.builder(params);
      paramBuilder.put(ParamName.GLOBAL_SINGLE_REQUEST_TIMEOUT,
          ParamName.GLOBAL_SINGLE_REQUEST_TIMEOUT.getDefaultValue());
      paramBuilder.put(ParamName.GLOBAL_BATCH_REQUEST_TIMEOUT,
          ParamName.GLOBAL_BATCH_REQUEST_TIMEOUT.getDefaultValue());
      config.setParams(paramBuilder.build());
    }
    return config;
  }

  private static SecurityManagerConfig convertV1ConfigToV2(SecurityManagerConfig config) {
    ImmutableList.Builder<CredentialGroup> builder = ImmutableList.builder();
    Map<String, Integer> indices = Maps.newHashMap();
    for (CredentialGroup credentialGroup : config.getCredentialGroups()) {
      CredentialGroup.Builder groupBuilder = CredentialGroup.builder(credentialGroup);
      List<AuthnMechanism> mechanisms = groupBuilder.getMechanisms();
      mechanisms.clear();
      for (AuthnMechanism mech : credentialGroup.getMechanisms()) {
        String typeName = mech.getTypeName();
        int index = indices.containsKey(typeName) ? indices.get(typeName) : 0;
        index += 1;
        mechanisms.add(mech.copyWithNewName(typeName + "-" + index));
        indices.put(typeName, index);
      }
      builder.add(groupBuilder.build());
    }
    return SecurityManagerConfig.makeInternal(2, builder.build(), null, null);
  }

  private static SecurityManagerConfig convertV2ConfigToV3(SecurityManagerConfig config) {
    return SecurityManagerConfig.makeInternal(
        3,
        config.getCredentialGroups(),
        ConfigParams.makeDefault(),
        null);
  }

  private static SecurityManagerConfig convertV3ConfigToV4(SecurityManagerConfig config,
      JsonElement je) {
    JsonObject jo = je.getAsJsonObject();
    JsonObject globals = jo.getAsJsonObject("globals");
    ConfigParams params = config.getParams();
    return SecurityManagerConfig.makeInternal(
        4,
        config.getCredentialGroups(),
        (globals == null)
        ? params
        : ConfigParams.builder(params)
        .put(ParamName.GLOBAL_SINGLE_REQUEST_TIMEOUT,
            globals.getAsJsonPrimitive("singleRequestTimeoutSec").getAsFloat())
        .put(ParamName.GLOBAL_BATCH_REQUEST_TIMEOUT,
            globals.getAsJsonPrimitive("batchRequestTimeoutSec").getAsFloat())
        .build(),
        null);
  }

  private static SecurityManagerConfig convertV4ConfigToV5(SecurityManagerConfig config) {
    ConfigParams.Builder builder = ConfigParams.builder();
    ConfigParams oldParams = config.getParams();
    for (ParamName paramName : ConfigParams.keySet()) {
      if (paramName == ParamName.AUTHZ_CONFIG_FILENAME) {
        continue;
      }
      builder.put(paramName, oldParams.get(paramName));
    }
    return SecurityManagerConfig.makeInternal(
        5,
        config.getCredentialGroups(),
        builder.build(),
        null);
  }

  private static SecurityManagerConfig convertV5ConfigToV6(SecurityManagerConfig config) {
    ConfigParams.Builder builder = ConfigParams.builder();
    ConfigParams oldParams = config.getParams();
    for (ParamName paramName : ConfigParams.keySet()) {
      if (paramName == ParamName.CONNECTOR_MANAGER_URLS) {
        continue;
      }
      builder.put(paramName, oldParams.get(paramName));
    }
    return SecurityManagerConfig.makeInternal(
        6,
        config.getCredentialGroups(),
        builder.build(),
        config.getFlexAuthorizer());
  }

  private static SecurityManagerConfig convertV6ConfigToV7(SecurityManagerConfig config) {
    ConfigParams.Builder configParamsBuilder = ConfigParams.builder();
    ConfigParams oldParams = config.getParams();
    for (ParamName paramName : ConfigParams.keySet()) {
      if (paramName == ParamName.TRUST_FILENAME) {
        continue;
      }
      configParamsBuilder.put(paramName, oldParams.get(paramName));
    }

    // Changes the authnId of PER_URL_ACL rules from LEGACY_AUTHN_ID to EMPTY_AUTHN_ID.
    // Modifying FlexAuthorizer in-place is very painful, because the table entries depend on the
    // rules, but we can't put our new rules in place until the old ones have been removed. Instead,
    // we make all our changes in our own data structures and then clear the FlexAuthorizer and copy
    // our modifications in place.
    FlexAuthorizer flexAuthorizer = config.getFlexAuthorizer();
    Collection<FlexAuthzRule> newRules = Lists.newArrayList();
    // The order of these entries is very important.
    List<FlexAuthzRoutingTableEntry> newTableEntries = Lists.newArrayList();
    Map<FlexAuthzRule, FlexAuthzRule> oldToNew = Maps.newHashMap();
    for (FlexAuthzRule rule : flexAuthorizer.getAllRulesTable()) {
      if (AuthzMechanism.PER_URL_ACL.equals(rule.getAuthzMechType())) {
        FlexAuthzRule newRule = new FlexAuthzRule(FlexAuthzRule.EMPTY_AUTHN_ID,
            rule.getAuthzMechType(), rule.getMechSpecificParams(), rule.getRowDisplayName(),
            rule.getTimeout());
        oldToNew.put(rule, newRule);
        rule = newRule;
      }
      newRules.add(rule);
    }
    for (FlexAuthzRoutingTableEntry routing : flexAuthorizer.getAllRoutingTable()) {
      FlexAuthzRule newRule = oldToNew.get(routing.getAuthzRule());
      if (newRule != null) {
        routing = new FlexAuthzRoutingTableEntry(
            routing.getUrlPattern(), newRule, routing.getUniqueRowId());
      }
      newTableEntries.add(routing);
    }
    flexAuthorizer.clearTables();
    for (FlexAuthzRule rule : newRules) {
      flexAuthorizer.addToRulesTable(rule);
    }
    for (FlexAuthzRoutingTableEntry routing : newTableEntries) {
      flexAuthorizer.addToRoutingTable(routing);
    }

    // Add the Groups authn module to all credential groups.
    ImmutableList.Builder<CredentialGroup> credentialGroupBuilder = ImmutableList.builder();
    for (CredentialGroup credentialGroup : config.getCredentialGroups()) {
      CredentialGroup.Builder groupBuilder = CredentialGroup.builder(credentialGroup);
      List<AuthnMechanism> mechanisms = groupBuilder.getMechanisms();
      mechanisms.add(AuthnMechGroups.makeForCredentialGroup(credentialGroup.getName()));
      credentialGroupBuilder.add(groupBuilder.build());
    }

    return SecurityManagerConfig.makeInternal(
        7,
        credentialGroupBuilder.build(),
        configParamsBuilder.build(),
        flexAuthorizer);
  }

  private static SecurityManagerConfig convertV7ConfigToV8(SecurityManagerConfig config) {
    FlexAuthorizer flexAuthorizer = config.getFlexAuthorizer();
    // Since version 8, FILE_SYSTEM rules are not supported, thus we need to remove them.
    // We can't remove a rule that has a reference in the routing table,
    // so we find all routing rules that correspond to rules we need to remove,
    // then we remove those routing rule entries, and finally, remove the routing rules.
    Set<String> rulesToRemove = new HashSet<String>();
    Set<UUID> routingEntriesToRemove = new HashSet<UUID>();
    for (FlexAuthzRoutingTableEntry routingRule : flexAuthorizer.getAllRoutingTable()) {
      final FlexAuthzRule rule = routingRule.getAuthzRule();
      if (!AuthzMechanism.FILE_SYSTEM.equals(rule.getAuthzMechType())) {
        continue;
      }
      routingEntriesToRemove.add(routingRule.getUniqueRowId());
      rulesToRemove.add(rule.getRowDisplayName());
    }

    for (UUID uuid : routingEntriesToRemove) {
      flexAuthorizer.deleteFromRoutingTable(uuid);
    }

    for (String displayName : rulesToRemove) {
      final FlexAuthzRule ruleToRemove = flexAuthorizer.getFromRulesTable(displayName);
      flexAuthorizer.deleteFromRulesTable(ruleToRemove.getRowDisplayName());
    }

    return SecurityManagerConfig.makeInternal(
        8,
        config.getCredentialGroups(),
        config.getParams(),
        config.getFlexAuthorizer());
  }

  private static final Gson V0_SMC_GSON
      = new GsonBuilder()
          .registerTypeAdapter(AuthnMechanism.class,
              ProxyTypeAdapter.make(AuthnMechanism.class, V0AuthnMechanism.class))
          .registerTypeAdapter(CredentialGroup.class,
              ProxyTypeAdapter.make(CredentialGroup.class, V0CredentialGroup.class))
          .registerTypeAdapter(SecurityManagerConfig.class,
              ProxyTypeAdapter.make(SecurityManagerConfig.class, V0SecurityManagerConfig.class))
          .create();

  /** A type proxy for version 0 authn mechanism types. */
  public static final class V0AuthnMechanism implements TypeProxy<AuthnMechanism> {
    public String authority;
    public String sampleUrl;
    public String connectorManagerName;
    public String mechanism;
    public String adDomain;
    public String connectorName;
    public List<String> urlPatterns;
    public String redirectUrl;

    public V0AuthnMechanism() {
    }

    public V0AuthnMechanism(AuthnMechanism mechanism) {
      throw new UnsupportedOperationException();
    }

    @Override
    public AuthnMechanism build() {
      if (mechanism == null) {
        return null;
      }
      String name = SecurityManagerUtil.generateRandomNonceHex(8);
      if ("BASIC_AUTH".equals(mechanism)) {
        return AuthnMechBasic.make(name, Strings.emptyToNull(sampleUrl));
      }
      if ("FORMS_AUTH".equals(mechanism)) {
        return AuthnMechForm.make(name, Strings.emptyToNull(sampleUrl));
      }
      if ("NTLM_AUTH".equals(mechanism)) {
        return AuthnMechNtlm.make(name, Strings.emptyToNull(sampleUrl));
      }
      if ("SAML".equals(mechanism)) {
        return AuthnMechSaml.make(name, Strings.emptyToNull(authority));
      }
      if ("CONNECTORS".equals(mechanism)) {
        return AuthnMechConnector.make(name, Strings.emptyToNull(connectorName), false);
      }
      if ("SAMPLE_URL_CHECK".equals(mechanism)) {
        return AuthnMechSampleUrl.make(name, Strings.emptyToNull(sampleUrl),
            Strings.emptyToNull(redirectUrl));
      }
      if ("SURROGATE".equals(mechanism)) {
        return AuthnMechPreauthenticated.make(name);
      }
      throw new IllegalStateException("Unknown mechanism: " + mechanism);
    }
  }

  /** A type proxy for version 0 credential-group types. */
  public static final class V0CredentialGroup implements TypeProxy<CredentialGroup> {
    @SerializedName("Name") public String name;
    @SerializedName("DisplayName") public String displayName;
    public boolean requiresUsername;
    public boolean requiresPassword;
    @SerializedName("optional") public boolean isOptional;
    @SerializedName("Domains") public List<AuthnMechanism> mechanisms;

    public V0CredentialGroup() {
    }

    public V0CredentialGroup(CredentialGroup credentialGroup) {
      throw new UnsupportedOperationException();
    }

    @Override
    public CredentialGroup build() {
      if (name == null) {
        return null;
      }
      CredentialGroup.Builder builder =
          CredentialGroup.builder(name, displayName, requiresUsername, requiresPassword,
              isOptional);
      if (mechanisms != null) {
        for (AuthnMechanism mechanism : mechanisms) {
          if (mechanism != null) {
            builder.addMechanism(mechanism);
          }
        }
      }
      return builder.build();
    }
  }

  /** A type proxy for version 0 top-level configuration. */
  public static final class V0SecurityManagerConfig implements TypeProxy<SecurityManagerConfig> {
    @SerializedName("CGs") public List<CredentialGroup> credentialGroups;

    public V0SecurityManagerConfig() {
    }

    public V0SecurityManagerConfig(SecurityManagerConfig config) {
      throw new UnsupportedOperationException();
    }

    @Override
    public SecurityManagerConfig build() {
      ImmutableList.Builder<CredentialGroup> builder = ImmutableList.builder();
      for (CredentialGroup credentialGroup : credentialGroups) {
        if (credentialGroup != null) {
          builder.add(credentialGroup);
        }
      }
      return SecurityManagerConfig.makeInternal(1, builder.build(), null, null);
    }
  }
}
