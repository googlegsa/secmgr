// Copyright 2018 Google Inc.
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
package com.google.enterprise.ldap;


import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.enterprise.ldap.LDAPConstants.AuthMethod;
import com.google.enterprise.ldap.LDAPConstants.GroupResolutionFormat;
import com.google.enterprise.ldap.LDAPConstants.SSLSupport;
import com.google.enterprise.param.io.ConfigSerializer;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.util.Collection;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class deals with configuration parameters for LDAP.
 * 
 */

public class LDAPConfigManager {
  
  private static final Logger logger =
      Logger.getLogger(LDAPConfigManager.class.getName());
  private static Map<String, LDAPConfig> configMapOverride = null;
  
  private static LDAPConfigManager LDAP_CONFIGS_INSTANCE = null;
  
  private boolean oldConfigFormat = false;
  private Map<String, LDAPConfig> configMap = 
      Maps.<String, LDAPConfig>newLinkedHashMap();
  

  
  public enum ConfigField {
    HOSTPORTS("hostports"),
    HOSTPORT("hostport"),
    BASE("base"),
    USERSEARCHFILTER("userSearchFilter"),
    GROUPSEARCHFILTER("groupSearchFilter"),
    GROUPFORMAT("groupFormat"),
    ANONBINDDN("anonBindDN"),
    ANONBINDPASSWORD("anonBindPassword"),
    SSLSUPPORT("sslSupport"),
    AUTHMETHODS("authMethods");
    
    private String name;
    
    private ConfigField(String name) {
      this.name = name;
    }
    
    public String getName() {
      return name;
    }
  }
  
  private LDAPConfigManager() {}
  
  public static LDAPConfigManager getInstance() {
    if (LDAP_CONFIGS_INSTANCE == null) {
      LDAP_CONFIGS_INSTANCE = new LDAPConfigManager();      
    }
    return LDAP_CONFIGS_INSTANCE;
  }
  
  @VisibleForTesting
  public synchronized void setConfigMap(Map<String, LDAPConfig> configMap) {
    configMapOverride = configMap;
  }
  
  /**
   * Reads the ldap config.
   * @param reader a Reader which will be used to read the serialized
   * configuration parameters.
   * @see #read(java.io.Reader)
   */
  public synchronized boolean read(Reader reader) {
    if (configMapOverride != null) {
      return true;
    }
    oldConfigFormat = false;
    ConfigSerializer config = new ConfigSerializer();
    Iterable<String> hostportsList;
    try {
      config.read(reader);
    } catch (IOException e) {
      logger.log(Level.SEVERE, "Failed to read LDAP configuration", e);
      return false;
    }
    
    // parse the config names into iterable
    String hostportsRaw = config.get(ConfigField.HOSTPORTS.getName(), "");
    // if it is an non-empty old config format, we need to add the default config name
    // and update the config file when writing new config
    if (Strings.isNullOrEmpty(hostportsRaw.trim())) {
      if (!Strings.isNullOrEmpty(config.get(ConfigField.HOSTPORT.getName()))) {
        oldConfigFormat = true;
        String hostport = config.get(ConfigField.HOSTPORT.getName());
        hostportsList = Lists.newArrayList(hostport);
      } else {
        hostportsList = Lists.newArrayList();
      }
    } else {
      hostportsList = Splitter.on(',').trimResults().split(hostportsRaw);
    }
    
    configMap = Maps.<String, LDAPConfig>newLinkedHashMap();
    for (String name : hostportsList) {
      // the old config does not have prefix
      // ConfigSerializer use ':' as delimiter, so we change ':' to '#' here
      String prefix = name.replace(':', '#') + "_";
      
      if (oldConfigFormat) {
        prefix = "";
      }
      LDAPConfig ldapConfig = getLdapConfigFromConfig(config, oldConfigFormat, prefix);
      if (null == ldapConfig) {
        return false;
      }
      configMap.put(ldapConfig.getHostPort(), ldapConfig);
    } 
    return true;
  }
  
  private static LDAPConfig getLdapConfigFromConfig(ConfigSerializer config, 
      boolean oldConfigFormat, String prefix) {
    String hostport = config.get(prefix + ConfigField.HOSTPORT.getName(), "");
    String base = config.get(prefix + ConfigField.BASE.getName(), "");
    String userSearchFilter = config.get(prefix + ConfigField.USERSEARCHFILTER.getName(), "");
    String groupSearchFilter = config.get(prefix + ConfigField.GROUPSEARCHFILTER.getName(), "");
    String groupFormat = config.get(prefix + ConfigField.GROUPFORMAT.getName(), "");
    String anonBindDN = config.get(prefix + ConfigField.ANONBINDDN.getName(), "");
    String anonBindPassword = config.get(prefix + ConfigField.ANONBINDPASSWORD.getName(), "");
    String sslSupport = config.get(prefix + ConfigField.SSLSUPPORT.getName(), "");
    String authMethod = config.get(prefix + ConfigField.AUTHMETHODS.getName(), "");
    SSLSupport ssl ;
    AuthMethod auth;
    if(oldConfigFormat) {
      try {
        ssl = SSLSupport.fromInt(Integer.parseInt(sslSupport));
      } catch (NumberFormatException e) {
        logger.log(Level.SEVERE, "Could parse sslSupport", e);
        return null;
      }try {
        auth = AuthMethod.fromInt(Integer.parseInt(authMethod));
      } catch (NumberFormatException e) {
        logger.log(Level.SEVERE, "Could parse authMethod", e);  
        return null;
      }        
    } else {
      ssl = SSLSupport.fromString(sslSupport);
      auth = AuthMethod.fromString(authMethod);
    }
    if (ssl == SSLSupport.INVALID) {        
      ssl = SSLSupport.NO_SSL;
    }
    if (auth == AuthMethod.INVALID) {
      auth = AuthMethod.SIMPLE;
    }
    GroupResolutionFormat format = GroupResolutionFormat.fromString(groupFormat);
    if (format == GroupResolutionFormat.INVALID) {
      format = GroupResolutionFormat.CN;
    }
    return new LDAPConfig(hostport, base, userSearchFilter, 
        groupSearchFilter, anonBindDN, anonBindPassword, ssl, auth, format);
  }
  /**
   * Writes all the ldap configs to the specified Writer.
   * @param writer a Writer object used to write the configuration parameters.
   * @return true if configuration was successfully written. false otherwise.
   * @see #read(java.io.Reader)
   */
  public synchronized boolean write(Writer writer) {
    ConfigSerializer config = new ConfigSerializer();
    StringBuilder hostportsBuilder = new StringBuilder();
    String delimiter = "";
    for (String hostport : configMap.keySet()) {
      hostportsBuilder.append(delimiter  + hostport);
      if (delimiter.equals("")) {
        delimiter = ",";
      }
      
      LDAPConfig ldapConfig = configMap.get(hostport);
      String prefix = hostport.replace(':', '#') + "_";
      
      config.set(prefix + ConfigField.HOSTPORT.getName(), ldapConfig.getHostPort());
      config.set(prefix + ConfigField.BASE.getName(), ldapConfig.getBase());
      config.set(prefix + ConfigField.USERSEARCHFILTER.getName(), ldapConfig.getUserSearchFilter());
      config.set(prefix + ConfigField.GROUPSEARCHFILTER.getName(), 
          ldapConfig.getGroupSearchFilter());
      config.set(prefix + ConfigField.GROUPFORMAT.getName(), 
          ldapConfig.getGroupResolutionFormat().toString());
      config.set(prefix + ConfigField.ANONBINDDN.getName(), ldapConfig.getAnonBindDN());
      config.set(prefix + ConfigField.ANONBINDPASSWORD.getName(), 
          ldapConfig.getAnonBindPassword());
      config.set(prefix + ConfigField.SSLSUPPORT.getName(), 
          ldapConfig.getSSLSupportType().toString());
      config.set(prefix + ConfigField.AUTHMETHODS.getName(), ldapConfig.getAuthMethod().toString());
    }
    
    config.set(ConfigField.HOSTPORTS.getName(), hostportsBuilder.toString());
    
    try {
      config.write(writer);
    } catch (IOException e) {
      logger.log(Level.SEVERE, "Failed to get LDAPConfigs string", e);
      return false;
    }   
    return true;
  }

  /**
   * Get the LDAP config for the given hostport string
   * @param hostport hostport string for the ldap config to retrieve.
   * @return {@link LDAPConfig}
   */
  public synchronized LDAPConfig getSingleLDAPConfig(String hostport) {
    LDAPConfig ldapConfig = configMap.get(hostport);
    if (ldapConfig == null) {
      ldapConfig = new LDAPConfig();
    }
    return ldapConfig;
  }
  
  /**
   * Gets all the LDAP configs.
   * @return collection of all LDAP configs. 
   */
  public synchronized Collection<LDAPConfig> getAllConfigs() {
    return configMap.values();
  }
  
  /**
   * Gets the key value pairs for hostport and the corresponding LDAP config.
   * @return Map of ldap configs.
   */
  public synchronized Map<String, LDAPConfig> getConfigMap() {
    return ImmutableMap.copyOf(configMap);
  }
  
  /**
   * Deletes a given LDAP config from the map.
   * @param ldapConfig to delete.
   */
  public synchronized void deleteConfig(LDAPConfig ldapConfig) {
    configMap.remove(ldapConfig.getHostPort());
  }
  
  /**
   * Updates a given LDAP config in the config map.
   * @param ldapConfig to update.
   */
  public synchronized void updateConfig(LDAPConfig ldapConfig) {
    configMap.put(ldapConfig.getHostPort(), ldapConfig);
  }
  
  /**
   * Returns true if the config is a pre-7.0 config.
   * @return true if the config is a pre-7.0 config.
   */
  public synchronized boolean isOldConfigFormat() { return oldConfigFormat; }      
}
