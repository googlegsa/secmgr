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

import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.enterprise.ldap.LDAPConstants.AuthMethod;
import com.google.enterprise.ldap.LDAPConstants.GroupResolutionFormat;
import com.google.enterprise.ldap.LDAPConstants.SSLSupport;

/**
 * Class for ldap config for one LDAP server.
 */
public class LDAPConfig {
  // Following are the actual fields containing configuration information
  // for connecting to the LDAP server.
  private String hostport = null;  // <host>[:<port>] of LDAP server.
  private String base = "";        // component of DN common to all users.
  private String userSearchFilter = "";  // filter used to search for user.
  private String groupSearchFilter = ""; // filter used to find user's groups

  // The default timeout is the same as in secmgr.config.AuthnMechanism.NO_TIME_LIMIT
  private int timeout = -1;        // connection and read timeout in milliseconds.
                                   // -1 means no timeout.

  // Credentials used when detecting LDAP configuration parameters.
  // these should be empty if the server supports anonymous binding.
  private String anonBindDN = "";
  private String anonBindPassword = "";

  private SSLSupport sslSupport = SSLSupport.NO_SSL;
  private AuthMethod authMethod = AuthMethod.SIMPLE;
  private GroupResolutionFormat groupResFormat = GroupResolutionFormat.CN;
  
  public LDAPConfig() {}
  
  public LDAPConfig(String hostport, String base, String userSearchFilter,
      String groupSearchFilter, String anonBindDN, String anonBindPassword,
      SSLSupport sslSupport, AuthMethod authMethods, GroupResolutionFormat format) {
    this.hostport = hostport;
    this.base = base;
    this.userSearchFilter = userSearchFilter;
    this.groupSearchFilter = groupSearchFilter;
    this.anonBindDN = anonBindDN;
    this.anonBindPassword = anonBindPassword;
    this.sslSupport = sslSupport;
    this.authMethod = authMethods;
    this.groupResFormat = format;
   
  }
  
  public LDAPConfig copy() {
    return new LDAPConfig(this.hostport, this.base, this.userSearchFilter,
        this.groupSearchFilter, this.anonBindDN, this.anonBindPassword, this.sslSupport,
        this.authMethod, this.groupResFormat);
  }
  
  /** hostport is of the form <host>[:<port>] */
  public String getHostPort() { return hostport; }
  
  /** hostport is of the form <host>[:<port>] */
  public void setHostPort(String hostPort) { 
    hostport = hostPort.trim(); 
    this.hostport = hostPort;       
  }

  public String getHost() {
    return Splitter.on(':').trimResults().splitToList(hostport).get(0);
  }
  
  public String getPort() {
    return Splitter.on(':').trimResults().splitToList(hostport).get(1);
  }
  
  /** @return true if host has not yet been set. */
  public boolean noHost() {
    return Strings.isNullOrEmpty(hostport);
  }

  public int getTimeout() { return timeout; }
  public void setTimeout(int timeout) { this.timeout = timeout; }

  public String getBase() { return base; }
  public void setBase(String base) { this.base = base.trim(); }


  public String getUserSearchFilter() { return userSearchFilter; }
  /**
   * Set the user search filter.
   * @param userSearchFilter the filter expression. This should contain the
   * substring %s which will be replaced by the user name when searching for
   * the full user DN.
   */
  public void setUserSearchFilter(String userSearchFilter) {
    this.userSearchFilter = userSearchFilter;
  }

  public String getGroupSearchFilter() { return groupSearchFilter; }
  /**
   * Set the user search filter.
   * @param groupSearchFilter the filter expression. This should contain the
   * substring %s which will be replaced by the user name when searching for
   * the full user DN.
   */
  public void setGroupSearchFilter(String groupSearchFilter) {
    this.groupSearchFilter = groupSearchFilter;
  }

  public SSLSupport getSSLSupportType() { return sslSupport; }
  public void setSSLSupportType(SSLSupport sslSupportType) {
    this.sslSupport = sslSupportType;
  }

  public GroupResolutionFormat getGroupResolutionFormat() { return groupResFormat; }
  public void setGroupResolutionFormat(GroupResolutionFormat format) {
    groupResFormat = format;
  }

  public AuthMethod getAuthMethod() { return authMethod; }
  public void setAuthMethod(AuthMethod authMethod) {
    this.authMethod = authMethod;
  }

  /**
   * Sets the credentials used for binding to the LDAP server for general
   * (non user specific) searches. For instance to get different DNs matching
   * same user name, or for identifying base DN.
   */
  public void setAnonBindIdentity(String dn, String password) {
    this.anonBindDN = dn;
    this.anonBindPassword = password;
  }
  public String getAnonBindDN()        { return anonBindDN; }
  public String getAnonBindPassword()  { return anonBindPassword; }  
}