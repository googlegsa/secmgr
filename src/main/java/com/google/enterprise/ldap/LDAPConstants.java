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

/**
 * Class to hold static constants for ldap.
 */
public class LDAPConstants {

  /**
   * Enum for selecting which group format to resolve from LDAP / AD lookups during group
   * resolution.  See bugs http://b/issue?id=6568192, http://b/issue?id=2289644, and
   * http://b/issue?id=5520819 for reference.
   */
  public static enum GroupResolutionFormat {
    CN,  // Legacy behavior.
    DN,  // The full DN.
    SAM_ACCOUNT_NAME,  // sAMAccountName field
    INVALID;

    public static GroupResolutionFormat fromString(String string) {
      if (string == null) {
        return INVALID;
      }
      try {
        return valueOf(GroupResolutionFormat.class, string);
      } catch (IllegalArgumentException e) {
        return INVALID;
      }
    }
  }
  
  public static enum SSLSupport {
    NO_SSL(0),     // No SSL: password sent in the clear.
    TLS_SSL(1),    // LDAP over SSL.
    START_TLS(2),  // Start TLS extended ldap operation.
    INVALID(-1);
    
    private int sslType;
    
    private SSLSupport(int sslType) {
      this.sslType = sslType;
    }
    
    public int getSslType() {
      return sslType;
    }
    
    public static SSLSupport fromInt(int x) {
      for (SSLSupport sslSupport : SSLSupport.values()) {
        if (sslSupport.getSslType() == x)
            return sslSupport;
    }
      return INVALID;
    }
    
    public static SSLSupport fromString(String string) {
      if (string == null) {
        return INVALID;
      }
      try {
        return valueOf(SSLSupport.class, string);
      } catch (IllegalArgumentException e) {
        return INVALID;
      }
    }
  }
  
  public static enum AuthMethod {
    SIMPLE(0x0001),
    NONE(0x0000),
    ALL(0xffff),
    INVALID(-1);
    
    private int bit;
    
    private AuthMethod(int bit) {
      this.bit = bit;
    }
    
    public int getInt() {
      return bit;
    }
    
    public static AuthMethod fromInt(int x) {
      for (AuthMethod authMethod : AuthMethod.values()) {
        if (authMethod.getInt() == x)
            return authMethod;
    }
      return INVALID;
    }
    
    public static AuthMethod fromString(String string) {
      if (string == null) {
        return INVALID;
      }
      try {
        return valueOf(AuthMethod.class, string);
      } catch (IllegalArgumentException e) {
        return INVALID;
      }
    }
  }
  
  //attribute containing high level naming contexts:
  public static final String baseDNAttribute = "namingContexts";

  //possible search filters for retrieving user information:
  public static final String RFC2307UserSearchFilter =
      "(&(objectClass=posixAccount)(uid=%s))";

  /**
   * This filter should work to get the username for all windows
   * servers from Windows 2000 to Windows 2008.  See
   * http://msdn.microsoft.com/en-us/library/ms679635(VS.85).aspx for more info.
   */
  public static final String activeDirectoryUserSearchFilter =
  "(&(objectClass=user)(objectClass=person)(sAMAccountName=%s))";
  
  public static final String[] userSearchFilters = {
    // uneducated guesses:
    "(uid=%s)",
    "(username=%s)",
    // standard filters:
    RFC2307UserSearchFilter,
    activeDirectoryUserSearchFilter,
  };
  
  public static final String RFC2307GroupSearchFilter = "(memberUid=%s)";
  public static final String activeDirectoryGroupSearchFilter =
      "(|(member=%dn)(member=%s))";


  // This operator will instruct Active Directory servers to do nested group
  // resolution when resolving groups.  See b/2873077 for more context.
  public static final String NESTED_LOOKUP_OPERATOR =
      ":1.2.840.113556.1.4.1941:=";

  public static final String ATTRIBUTE_DN = "dn";
  // Active directory DN attribute name
  public static final String ATTRIBUTE_AD_DN = "distinguishedName";
  public static final String ATTRIBUTE_SAM_ACCOUNT_NAME = "sAMAccountName";

  // Filters are tried first to last.  The first filter that returns a group
  // is the one that will be used.
  public static final String[] groupSearchFilters = {
    activeDirectoryGroupSearchFilter,
    RFC2307GroupSearchFilter
  };
  
  //context attribute used to detect if LDAP is Active Directory
  public static final String ATTR_DSSERVICENAME = "dsServiceName";  
  public static final String DIRECT_GROUPS_FILTER =
      "(&(objectClass=user)(distinguishedName=%s))";
  // Primary groups: "Domain Users" group and other default AD groups
  public static final String PRIMARY_GROUP_FILTER = "(objectSid=%s)";
  public static final String ATTRIBUTE_PRIMARY_GROUP_ID = "primaryGroupID";
  public static final String ATTRIBUTE_OBJECTSID = "objectSid;binary";
  public static final String ATTRIBUTE_MEMBER_OF = "memberOf";
  public static final String ATTRIBUTE_MAIL = "mail";  
  public static final String ATTRIBUTE_AD_NETBIOSNAME = "nETBIOSName";
  public static final String ATTRIBUTE_AD_DNSROOT = "dnsRoot";
  public static final String ATTRIBUTE_AD_CONFIGURATIONNAMINGCONTEXT = "configurationNamingContext";
  public static final String ATTRIBUTE_AD_DEFAULTNAMINGCONTEXT = "defaultNamingContext";
}
