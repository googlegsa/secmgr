// Copyright 2010 Google Inc.
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

package com.google.enterprise.secmgr.mock;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.enterprise.ldap.LDAPConfig;
import com.google.enterprise.ldap.LDAPConstants.GroupResolutionFormat;
import com.google.enterprise.secmgr.ldap.LDAPClient;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.naming.NamingException;

/**
 * A mock implementation of {@link LDAPClient} to avoid networking and file IO
 * and provide a primitive user/password/groups database for unittests.  All
 * public methods from the superclass that potentially touch the
 * network/filesystem have either been overridden or only call functions that
 * have been overridden or don't touch the network/filesystem.
 */
public class MockLDAPClient extends LDAPClient {
  public static final String GOOD_HOST_PORT = "localhost:1001";
  private static final String GOOD_DOMAIN_DN = "dc=esodomain,dc=com";
  private static final String GOOD_DOMAIN = "esodomain.com";
  
  /** A message used when throwing new exceptions. */
  private static final String EXCEPTION_MESSAGE =
      "Artificially generated exception";
  /**
   * A primitive database that maps users to groups.  This is used
   * to provide mock answers for calls to {@link #getGroupsWithUser}.
   */
  private Map<String, Set<String>> groupsDb;

  /**
   * A primitive database that maps users to passwords.  This is used
   * to provide mock answers for calls to
   * {@link #authenticate}.
   */
  private Map<String, String> userDb;

  /**
   * A primitive database that maps users to emails.  This is used
   * to provide mock answers for calls to {@link #getMail(String)}.
   */
  private Map<String, String> mailDb;

  /**
   * The functions {@link #authenticate}, {@link #getGroupsWithUser}, and
   * {@link #getMail} will throw {@link NamingException}s if this variable is
   * set to {@code true}.  This is used to test correct exception handling.
   * @see #setThrowNamingExceptions
   */
  private boolean throwNamingExceptions = false;

  /**
   * Instantiates a new MockLDAPClient with empty user/password
   * and user/groups databases.
   */
  public MockLDAPClient(LDAPConfig ldapConfig) {    
    super(ldapConfig);
    ldapConfig.setHostPort(GOOD_HOST_PORT);
    this.setLdapConfig(ldapConfig);
    userDb = Collections.emptyMap();
    groupsDb = Collections.emptyMap();
    mailDb = Collections.emptyMap();    
  }
  /**
   * Authenticates {@code user} against local username/password
   * database.
   * @param username
   * @param password
   * @return {@code username} on success, {@code null} on failure
   * @see LDAPClient#authenticate
   */
  @Override
  public String authenticate(String username, String password)
      throws NamingException {
    if (throwNamingExceptions) {
      throw new NamingException(EXCEPTION_MESSAGE);
    }
    String prefix = "";
    if (groupResolutionFormat() == GroupResolutionFormat.CN) {
      prefix = "cn=";
    }
    if (userDb.get(username) == password) {
      return prefix + username + "," + GOOD_DOMAIN_DN;
    } else { 
      return null;
    }
  }
  
  @Override
  public String getDomain(String dn) {
    return GOOD_DOMAIN;
  }

  /**
   * This simulates rewritting of domain from dnsRoot to nETBIOSName
   * Just does a substring based on the dnsRoot
   * @param filter contains dnsRoot to be rewritten
   * @param property ignored
   * @return nETBIOSName
  */
  @Override
  public String getADProperty(String filter, String property) {
    return filter.substring(filter.indexOf("REWRITE_TO_") + 11, filter.indexOf(")"));
  }
  
  /**
   * Does nothing, currently.  This method is overridden to keep
   * the logic of non-overridden methods intact while avoiding
   * the network.
   * @param info
   * @return true
   */
  @Override
  protected boolean detectBase(StringBuilder info) {
    return true;
  }

  /**
   * Does nothing, currently.
   * @return an uninitialized LDAPSettings object.
   * @see com.google.enterprise.ldap.LDAPClient#detectSettingsVerbose
   */
  @Override
  public LDAPSettings detectSettingsVerbose() {
    return new LDAPSettings();
  }

  /**
   * Does nothing, currently.  This method is overridden to keep
   * the logic of non-overridden methods intact while avoiding
   * the network.
   * @param info
   * @return true
   */
  @Override
  protected boolean detectSSLSupport(StringBuilder info) {
    return true;
  }

  /**
   * Returns a list of groups with which {@code username}
   * is associated.  This method maintains the superclass contract that
   * {@code null} is not returned.
   * @param username
   * @param dn the fully qualified DN for that user
   * @return a list of groups associated with that user in the
   * primitive groups database on success, and an empty
   * list on failure
   * @see LDAPClient#getGroupsWithUser
   */
  @Override
  public Set<NameAndDomain> getGroupsWithUser(String username, String dn)
      throws NamingException {
    if (throwNamingExceptions) {
      throw new NamingException(EXCEPTION_MESSAGE);
    }

      String prefix = "cn=";
      String postfix = "," + GOOD_DOMAIN_DN;
    if (groupsDb.containsKey(username)) {
      Set<NameAndDomain> groups = new HashSet<NameAndDomain>();
      for (String group : groupsDb.get(username)) {
        switch (groupResolutionFormat()) {
          case CN:
          case SAM_ACCOUNT_NAME:
            groups.add(new NameAndDomain(group, prefix + group + postfix));
            break;
          case DN:
            groups.add(new NameAndDomain(group, group));
            break;
          default:
            // TODO(b/18683919): go/enum-switch-lsc
        }
      }
      return groups;
    } else {
      return ImmutableSet.of();
    }
  }

  /**
   * Returns a list of groups with which {@code username}
   * is associated.  This method maintains the superclass contract that
   * {@code null} is not returned.
   * @param username
   * @return a list of groups associated with that user in the
   * primitive groups database on success, and an empty
   * list on failure
   * @see LDAPClient#getGroupsWithUser
   */
  @Override
  public Set<NameAndDomain> getGroupsWithUser(String username)
      throws NamingException {
    return getGroupsWithUser(username, null);
  }

  @Override
  public String getUserDN(String username) {
    return username + ",dc=esodomain,dc=com";
  }

  /**
   * Looks up {@code uid} in local username/email address
   * database and returns the result.
   * @param uid username
   * @return the email address associated with that user in the local
   * database initialized by {@link #setMailDb}, if an entry exists,
   * and null otherwise
   * @see LDAPClient#getMail
   */
  @Override
  public String getMail(String uid) throws NamingException {
    if (throwNamingExceptions) {
      throw new NamingException(EXCEPTION_MESSAGE);
    }
    return mailDb.get(uid);
  }

  /**
   * Does nothing, currently.  This method is overridden to keep
   * the logic of non-overridden methods intact while avoiding
   * the network.
   * @param allFilters
   * @param info
   * @return an empty String
   */
  @Override
  protected String getSearchFilter(String[] allFilters, StringBuilder info) {
    return "";
  }


  /**
   * Sets the user/groups database that is used in calls to
   * {@link #getGroupsWithUser} via a defensive copy.
   * No consistency checking is done with regard to the user/password
   * database (there may be a user who is associated with a list of
   * groups but who does not have an entry in the user/password database
   * and vice-versa).
   * @param groupsDb mapping from usernames -> groups with which those
   * usernames are associated
   */
  public void setGroupsDb(Map<String, Set<String>> groupsDb) {
    if (groupsDb == null) {
      return;
    } else {
      this.groupsDb = ImmutableMap.copyOf(groupsDb);
    }
  }

  /**
   * Sets the user/password database that is used in calls to
   * {@link #authenticate} via a defensive copy.
   * No consistency checking is done with regard to the user/groups
   * database (there may be a user who is associated with a list of
   * groups but who does not have an entry in the user/password database
   * and vice-versa).
   * @param userDb mapping from usernames -> passwords
   */
  public void setUserDb(Map<String, String> userDb) {
    if (userDb == null) {
      return;
    } else {
      this.userDb = ImmutableMap.copyOf(userDb);
    }
  }

  /**
   * Sets the user/email database that is used in calls to
   * {@link #getMail} via a defensive copy.
   * No consistency checking is done with regard to the user/groups
   * database (there may be a user who is associated with a list of
   * groups but who does not have an entry in the user/password database
   * and vice-versa) or the user/password database.
   * @param mailDb mapping from usernames -> email addresses
   */
  public void setMailDb(Map<String, String> mailDb) {
    if (mailDb == null) {
      return;
    } else {
      this.mailDb = ImmutableMap.copyOf(mailDb);
    }
  }

  public void setThrowNamingExceptions(boolean value) {
    throwNamingExceptions = value;
  }
}
