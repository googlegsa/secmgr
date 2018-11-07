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

package com.google.enterprise.secmgr.ldap;

import static com.google.common.truth.Truth.assertWithMessage;

import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.enterprise.ldap.LDAPConstants.AuthMethod;
import com.google.enterprise.ldap.LDAPConstants.GroupResolutionFormat;
import com.google.enterprise.ldap.LDAPConstants.SSLSupport;
import com.google.enterprise.secmgr.ldap.LDAPClient.NameAndDomain;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.util.Set;
import javax.naming.AuthenticationException;
import javax.naming.NamingException;

/**
 * Tests the basic LDAPClient functionality against a dedicated LDAP server.
 *
 * This is mostly copied from com.google.enterprise.ldap.LDAPClientTest, with
 * a few minor modifications.
 *
 * TODO: Small tests would be much preferrable, but
 * this will require some non-trivial refactoring to make a clean
 * seam between the network access and the rest of the logic.
 * TODO: As per the previous todo, we need to implement a way of testing LDAP
 * without relying on corp network (i.e. mock ldap server) before shipping this
 * as an off-board/open-source component.  One way of doing this would be to
 * convert this code to use the sec-mgr's HttpClient interface to handle
 * connections, so that we can test without relying on any network access
 * at all.
 */
public final class LDAPClientTest extends SecurityManagerTestCase {

  /** Configuration for an OpenLDAP server. **/
  private static final String GOOD_USER_SEARCH_FILTER = "(uid=%s)";
  private static final String GOOD_GROUP_SEARCH_FILTER = "(memberUid=%s)";
  private static final String GOOD_USERNAME = "binzie";
  private static final String GOOD_PASSWORD = "welcome";
  private static final String BAD_PASSWORD = "etigtmkfTGqwd9";  // irony, he he
  private static final String GOOD_FULL_DN =
      "uid=binzie,ou=engineer,dc=corp.google,dc=com";
  private static final String GOOD_FULL_DN_CAPS =
      "UID=binzie,OU=engineer,DC=corp.google,DC=com";
  private static final String GOOD_DOMAIN = "corp.google.com";

  // This user is not in any LDAP groups on the test server.
  private static final String GOOD_USERNAME_NO_GROUPS = "gib1";
  private static final String GOOD_BASE_DN = "dc=corp.google,dc=com";
  private static final String GOOD_HOST = "ent-test-ldap";
  private static final String BAD_HOST = "this-host-does-not-exist";
  private static final ImmutableSet<NameAndDomain> GROUPS_FOR_GOOD_USERNAME =
      ImmutableSet.of(
          new NameAndDomain("group_2", "cn=group_2,ou=Group,dc=corp.google,dc=com"),
          new NameAndDomain("group_1", "cn=group_1,ou=Group,dc=corp.google,dc=com"));

  /** Configuration for an Active Directory server. **/
  private static final String AD_BIND_DN =
      "CN=QA Admin,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com";
  private static final String AD_USERNAME = "QA Admin";
  private static final String AD_PASSWORD = "t3stth!s";
  private static final String AD_BASE_DN =
      "CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com";
  private static final String AD_ROOT_BASE_DN =
      "DC=ent-qa-d2,DC=corp,DC=google,DC=com";
  private static final String AD_USER_SEARCH_FILTER =
      "(&(objectClass=user)(objectClass=person)(name=%s))";
  private static final String AD_GROUP_SEARCH_FILTER = "(|(member=%dn)(member=%s))";
  private static final String AD_HOST = "cartier.mtv.corp.google.com";
  // user where sAMAccountName differs from commonName
  private static final String AD_SAMNECN = "cabot_ntlm";
  private static final String AD_SAMNECN_DN =
      "CN=ntlm test,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com";
  private static final NameAndDomain AD_SAMNECM_PRIMARY_GROUP =
      new NameAndDomain("Domain Users",
          "CN=Domain Users,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com");

  // These are details for an entry that has an email associated with it
  // to test the getMail() method.
  private static final String EMAIL_USERNAME = "uam5";
  private static final String EMAIL_ADDRESS = "nobody@google.com";

  private static final int GOOD_PORT = 389;
  private static final int BAD_PORT = -1;

  private static final ImmutableSet<NameAndDomain> GROUPS_FOR_AD_USERNAME =
      ImmutableSet.of(
          new NameAndDomain(
              "Domain Users", "CN=Domain Users,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com"),
          new NameAndDomain(
              "Schema Admins", "CN=Schema Admins,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com"),
          new NameAndDomain(
              "Domain Admins", "CN=Domain Admins,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com"));

  // Locations of test config files.
  private static final String NO_EXCEPTION_MESSAGE =
      "An exception should be thrown on a bad host";
  private static final ImmutableSet<NameAndDomain> FULL_DN_AD_GROUPS =
      ImmutableSet.of(
          new NameAndDomain(
              "CN=Domain Users,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com",
              "CN=Domain Users,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com"),
          new NameAndDomain(
              "CN=Schema Admins,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com",
              "CN=Schema Admins,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com"),
          new NameAndDomain(
              "CN=Domain Admins,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com",
              "CN=Domain Admins,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com"));

  private static final ImmutableSet<NameAndDomain> SAM_AD_GROUPS =
      ImmutableSet.of(
          new NameAndDomain(
              "Domain Users", "CN=Domain Users,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com"),
          new NameAndDomain(
              "Schema Admins", "CN=Schema Admins,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com"),
          new NameAndDomain(
              "Domain Admins", "CN=Domain Admins,CN=Users,DC=ent-qa-d2,DC=corp,DC=google,DC=com"));

  private LDAPClient ldapClient;

  @Override
  protected void setUp() throws Exception {
    super.setUp();
    ldapClient = new LDAPClient();
  }
  
  @Override
  protected void runTest() throws Throwable {
    //TODO: Ignore this test for now, it needs embedded / mock LDAP server
  }

  public static void setupGoodConfig(LDAPClient ldapClient) {
    ldapClient.setSSLSupportType(SSLSupport.NO_SSL);
    ldapClient.setSupportedAuthMethods(AuthMethod.SIMPLE);

    ldapClient.setBase(GOOD_BASE_DN);
    ldapClient.setUserSearchFilter(GOOD_USER_SEARCH_FILTER);
    ldapClient.setGroupSearchFilter(GOOD_GROUP_SEARCH_FILTER);
    ldapClient.setHostPort(GOOD_HOST + ":" + GOOD_PORT);
  }

  public void setupActiveDirectoryConfig(SSLSupport sslSetting) {
    ldapClient = new LDAPClient();
    ldapClient.setSSLSupportType(sslSetting);
    ldapClient.setSupportedAuthMethods(AuthMethod.SIMPLE);

    ldapClient.setBase(AD_BASE_DN);
    ldapClient.setAnonBindIdentity(AD_BIND_DN, AD_PASSWORD);
    ldapClient.setUserSearchFilter(AD_USER_SEARCH_FILTER);
    ldapClient.setGroupSearchFilter(AD_GROUP_SEARCH_FILTER);
    ldapClient.setHostPort(AD_HOST + ((sslSetting == SSLSupport.TLS_SSL) ? ":636" : ":389"));
  }


  /**
   * These cases don't test whether authenticate succeeds, only whether we can successfully
   * connect via the tls/ssl protocol.
   * debugging tip: if the testcase fails, remove the exception handling here to see the full
   * stack trace of the failure...
   */
  public void testStartTlsConnect() {
    setupActiveDirectoryConfig(SSLSupport.START_TLS);
    try {
      assertNull(ldapClient.authenticate("gsa", "foo"));
    } catch (Exception e) {
      e.printStackTrace();
      fail("Failed to connect via Start TLS.");
    }
  }

  public void testTlsSslConnect() {
    setupActiveDirectoryConfig(SSLSupport.TLS_SSL);
    try {
      assertNull(ldapClient.authenticate("gsa", "foo"));
    } catch (Exception e) {
      e.printStackTrace();
      fail("Failed to connect via TLS_SSL.");
    }
  }

/**
   * Ensure that valid settings are detected correctly without
   * throwing erroneous exceptions.
   * @see LDAPClient#detectSSLSupport
   */
  public void testDetectSSLSupport() {
    setupGoodConfig(ldapClient);

    StringBuilder builder = new StringBuilder();
    assertTrue("Incorrect SSL detection", ldapClient.detectSSLSupport(builder));
    assertNotEquals("Incorrect status reporting for SSL", -1, builder.toString()
        .indexOf("No TLS or TLS/SSL support detected"));
    assertEquals("SSL setting not correctly set", SSLSupport.NO_SSL, ldapClient.sslSupportType());

    // TODO: this is somewhat odd behavior and should
    // be changed to something more intuitive.  The LDAP
    // host used here does not exist, and the function returns 'true'
    // and simply sets the SSL support to be NO_SSL.
    ldapClient.setHostPort(BAD_HOST + ":" + BAD_PORT);
    builder = new StringBuilder();
    assertTrue("Incorrect SSL detection", ldapClient.detectSSLSupport(builder));
    assertEquals("SSL setting not correctly set", SSLSupport.NO_SSL, ldapClient.sslSupportType());
  }

  /**
   * Ensure that valid settings are detected correctly without
   * throwing erroneous exceptions.
   * @see LDAPClient#detectGroupSearchFilter()
   */
  public void testDetectGroupSearchFilter() {
    setupGoodConfig(ldapClient);

    assertTrue("Group search filter not detected correctly",
        ldapClient.detectGroupSearchFilter());
    assertEquals("Incorrect group search filter",
        GOOD_GROUP_SEARCH_FILTER, ldapClient.groupSearchFilter());

    ldapClient.setHostPort(BAD_HOST + ":" + BAD_PORT);
    assertFalse("Group search filter detected with invalid server",
        ldapClient.detectGroupSearchFilter());
  }

  /**
   * Ensure that valid settings are detected correctly without
   * throwing erroneous exceptions.
   * @see LDAPClient#detectBase
   */
  public void testDetectBase() {
    setupGoodConfig(ldapClient);

    assertTrue("Base dn not detected correctly", ldapClient.detectBase(null));
    assertEquals("Incorrect base dn", GOOD_BASE_DN, ldapClient.base());

    ldapClient.setHostPort(BAD_HOST + ":" + BAD_PORT);
    assertFalse("Base dn not detected correctly", ldapClient.detectBase(null));
    assertTrue("Base incorrectly set", Strings.isNullOrEmpty(ldapClient.base()));
  }

  /**
   * Ensure that valid settings are detected correctly without
   * throwing erroneous exceptions.
   * @see LDAPClient#detectUserSearchFilter
   */
  public void testDetectUserSearchFilter() {
    setupGoodConfig(ldapClient);

    StringBuilder builder = new StringBuilder();
    assertTrue("User search filter not detected correctly",
        ldapClient.detectUserSearchFilter(builder));
    assertEquals("Incorrect problem reported", -1, builder.toString()
        .indexOf("Problem while getting filter"));
    assertEquals("Incorrect user search filter",
        GOOD_USER_SEARCH_FILTER, ldapClient.userSearchFilter());

    ldapClient.setHostPort(BAD_HOST + ":" + BAD_PORT);
    assertFalse("User search filter not detected correctly",
        ldapClient.detectUserSearchFilter(builder));
    assertTrue("User search filter incorrectly set",
        Strings.isNullOrEmpty(ldapClient.userSearchFilter()));
  }

  /**
   * Verify that the verbose mode for detection of settings
   * returns the same results as the non-verbose-option-equivalent calls
   * and produces a sensible output string.
   * @see LDAPClient#detectSettingsVerbose()
   */
  public void testDetectSettingsVerbose() {
    setupGoodConfig(ldapClient);
    String verboseOutput =
        ldapClient.detectSettingsVerbose().toVerboseString(true);
    assertEquals("Incorrect base dn", GOOD_BASE_DN, ldapClient.base());
    assertEquals("Incorrect user search filter",
        GOOD_USER_SEARCH_FILTER, ldapClient.userSearchFilter());
    assertEquals("Incorrect group search filter",
        GOOD_GROUP_SEARCH_FILTER, ldapClient.groupSearchFilter());
    assertEquals("SSL setting not correctly set", SSLSupport.NO_SSL, ldapClient.sslSupportType());

    assertNotEquals("Base not found in verbose string", -1,
        verboseOutput.indexOf(GOOD_BASE_DN));
    assertNotEquals("User search filter not found in verbose string", -1,
        verboseOutput.indexOf(GOOD_USER_SEARCH_FILTER));
    assertNotEquals("SSL setting not found in verbose string", -1,
        verboseOutput.indexOf("No TLS or TLS/SSL support detected"));
    // For some reason the group filter has no verbose option and
    // is not included in the verbose output.
  }

  /**
   * Ensure basic authentication works as expected.
   * @throws javax.naming.NamingException if there was any
   * problem with the LDAP server request such as a bad server configuration
   * or incorrect/improper parameters
   * @see LDAPClient#authenticate
   */
  public void testAuthenticate() throws NamingException {
    setupGoodConfig(ldapClient);

    assertEquals("Unsuccessful authentication", GOOD_FULL_DN,
        ldapClient.authenticate(GOOD_USERNAME, GOOD_PASSWORD));

    assertNull("Authentication should have failed",
        ldapClient.authenticate(GOOD_USERNAME, BAD_PASSWORD));

    ldapClient.setHostPort(BAD_HOST + ":" + BAD_PORT);
    try {
      ldapClient.authenticate(GOOD_USERNAME, BAD_PASSWORD);
      fail(NO_EXCEPTION_MESSAGE);
    } catch (NamingException e) {
      // This is expected behavior.
    }
  }

  // TODO: ensure proper error handling when
  // there are odd userSearchFilters/groupSearchFilters (found that
  // bug a while ago)

  /**
   * Verify correct groups are returned for various users.
   * @throws javax.naming.NamingException if there was any
   * problem with the LDAP server request such as a bad server configuration
   * or incorrect/improper parameters
   * @see LDAPClient#getGroupsWithUser
   */
  public void testGetGroupsWithUser() throws NamingException {
    setupGoodConfig(ldapClient);

    Set<NameAndDomain> groupsForGoodUsername = ldapClient.getGroupsWithUser(GOOD_USERNAME);
    assertEquals("Incorrect number of groups for user", GROUPS_FOR_GOOD_USERNAME.size(),
        groupsForGoodUsername.size());
    assertEquals(GROUPS_FOR_GOOD_USERNAME, groupsForGoodUsername);
    assertTrue("Groups not empty",
        ldapClient.getGroupsWithUser(GOOD_USERNAME_NO_GROUPS).isEmpty());

    ldapClient.setHostPort(BAD_HOST + ":" + BAD_PORT);
    try {
      ldapClient.getGroupsWithUser(GOOD_USERNAME);
      fail(NO_EXCEPTION_MESSAGE);
    } catch (NamingException e) {
      // This is expected behavior.
    }
  }

  /**
   * Verify that group detection works correctly with an Active Directory
   * server.  See bug 1994132, bug 6132156 for more details.
   */
  public void testGetGroupsWithAd() throws NamingException {
    setupActiveDirectoryConfig(SSLSupport.NO_SSL);

    String dn = ldapClient.authenticate(AD_USERNAME, AD_PASSWORD);

    Set<NameAndDomain> groupsForADUsername =
        ldapClient.getGroupsWithUser(AD_USERNAME, dn);
    assertEquals("Incorrect number of groups for user", GROUPS_FOR_AD_USERNAME.size(),
        groupsForADUsername.size());
    assertEquals(GROUPS_FOR_AD_USERNAME, groupsForADUsername);

    assertTrue("Groups not empty",
        ldapClient.getGroupsWithUser(AD_USERNAME).isEmpty());
  }

  public void testPrimaryGroupResolution() throws NamingException {
    setupActiveDirectoryConfig(SSLSupport.NO_SSL);
    Set<NameAndDomain> groups = ldapClient.getGroupsWithUser(AD_SAMNECN, AD_SAMNECN_DN);
    assertWithMessage("Primary group").that(groups).contains(AD_SAMNECM_PRIMARY_GROUP);
  }


  public void testPrimaryGroupResolutionWithRootDN() throws NamingException {
    setupActiveDirectoryConfig(SSLSupport.NO_SSL);
    ldapClient.setBase(AD_ROOT_BASE_DN);
    Set<NameAndDomain> groups = ldapClient.getGroupsWithUser(AD_SAMNECN, AD_SAMNECN_DN);
    assertWithMessage("Primary group").that(groups).contains(AD_SAMNECM_PRIMARY_GROUP);
  }
  /**
   * Verify that DNs with escaped characters are properly escaped during
   * group lookup and that the user is properly authenticated.  See bugs
   * 222207 and 2140743.
   */
  /* TODO: Uncomment this test once the server has been properly
   * configured.  Right now access is blocked for some reason and I don't want to
   * add another dependency on a different server.  I have tested the bug fix manually
   * on a different server where the DN contains ',', '#', '/', and '\'.
  public void testProperEscaping() throws NamingException {
    readSettings(AD_CONFIG_FILE);

    String dn = ldapClient.authenticate(AD_ESCAPING_USERNAME, AD_ESCAPING_PASSWORD);

    assertEquals("Incorrect groups found for user", GROUPS_FOR_AD_ESCAPING_USERNAME,
        ldapClient.getGroupsWithUser(AD_ESCAPING_USERNAME, dn));
  }
  */

  // Verify group resolution using full DN is working properly.
  public void testNestedGroupResolutionFullDn() throws NamingException {
    setupActiveDirectoryConfig(SSLSupport.NO_SSL);
    ldapClient.setGroupResolutionFormat(GroupResolutionFormat.DN);
    String dn = ldapClient.authenticate(AD_USERNAME, AD_PASSWORD);

    assertEquals("Incorrect groups found for user", FULL_DN_AD_GROUPS,
        ldapClient.getGroupsWithUser(AD_USERNAME, dn));
  }

  // Verify group resolution using SAM_ACCOUNT_NAME is working properly.
  public void testNestedGroupResolutionSamAccountName() throws NamingException {
    setupActiveDirectoryConfig(SSLSupport.NO_SSL);
    ldapClient.setGroupResolutionFormat(GroupResolutionFormat.SAM_ACCOUNT_NAME);
    String dn = ldapClient.authenticate(AD_USERNAME, AD_PASSWORD);
    assertEquals("Incorrect groups found for user", SAM_AD_GROUPS,
        ldapClient.getGroupsWithUser(AD_USERNAME, dn));
  }

  public void testBaseDnCaseSensitivity() throws NamingException {
    setupActiveDirectoryConfig(SSLSupport.NO_SSL);
    ldapClient.setBase(AD_BASE_DN.toLowerCase());
    assertEquals(AD_BIND_DN, ldapClient.getUserDN(AD_USERNAME));
    assertEquals(AD_BIND_DN, ldapClient.authenticate(AD_USERNAME, AD_PASSWORD));
    ldapClient.setBase(AD_BASE_DN.toUpperCase());
    assertEquals(AD_BIND_DN, ldapClient.getUserDN(AD_USERNAME));
    assertEquals(AD_BIND_DN, ldapClient.authenticate(AD_USERNAME, AD_PASSWORD));
  }

  /**
   * Verify correct email addresses are returned.
   * @throws javax.naming.NamingException if there was any
   * problem with the LDAP server request such as a bad server configuration
   * or incorrect/improper parameters
   * @see LDAPClient#getMail
   */
  public void testGetMail() throws NamingException {
    setupGoodConfig(ldapClient);
    assertNull("Email address returned for user without email",
        ldapClient.getMail(GOOD_USERNAME));

    assertEquals("Incorrect email address returned",
        EMAIL_ADDRESS, ldapClient.getMail(EMAIL_USERNAME));

    ldapClient.setHostPort(BAD_HOST + ":" + BAD_PORT);
    try {
      ldapClient.getMail(GOOD_USERNAME);
      fail(NO_EXCEPTION_MESSAGE);
    } catch (NamingException e) {
      // This is expected behavior.
    }
  }

  /**
   * Ensure the filter replacement of usernames and dns will
   * work correctly.
   */
  public void testReplaceInFilter() {
    assertEquals("hey",
        ldapClient.replaceInFilter("%s", "%s", "hey"));

    assertEquals("hey hey",
        ldapClient.replaceInFilter("%s %s", "%s", "hey"));

    assertEquals("hey",
        ldapClient.replaceInFilter("%dn", "%dn", "hey"));

    assertEquals("no target",
        ldapClient.replaceInFilter("no target", "%s", "hey"));

    assertEquals("%s",
        ldapClient.replaceInFilter("%s", "%s", ""));

    assertEquals("%s",
        ldapClient.replaceInFilter("%s", "%s", null));

    assertEquals("%s",
        ldapClient.replaceInFilter("%s", "", "hey"));

    assertEquals("%s",
        ldapClient.replaceInFilter("%s", null, "hey"));

    assertEquals("",
        ldapClient.replaceInFilter("", "%s", "hey"));

    assertEquals(null,
        ldapClient.replaceInFilter(null, "%s", "hey"));
  }

  // Unfortunately, this is not one of the junit asserts nor is
  // it part of com.google.testing.util.MoreAsserts.
  private void assertNotEquals(final String message, int expected, int actual) {
    if (expected != actual) {
      return;
    }
    fail(message + ": expected " + expected + ", actual " + actual);
  }

  public void testGetDomain() throws NamingException {
    setupGoodConfig(ldapClient);
    String domain = ldapClient.getDomain(GOOD_FULL_DN);
    assertEquals(GOOD_DOMAIN, domain);
    domain = ldapClient.getDomain(GOOD_FULL_DN_CAPS);
    assertEquals(GOOD_DOMAIN, domain);

    assertNull(ldapClient.getDomain(null));
    assertNull(ldapClient.getDomain(""));
    assertNull(ldapClient.getDomain("asdf"));

    // no domain attribute ("dc" or "DC") on this string
    assertNull(ldapClient.getDomain("uid=binzie,ou=engineer,bc=corp.google,bc=com"));

    // the string "dc" in attribute values should not affect parsing
    assertNull(ldapClient.getDomain("uid=dc,ou=dc,bc=corp.google,bc=com"));

    // oh boy
    domain = ldapClient.getDomain("uid=dc,ou=dc,dc=dc.corp,dc=com");
    assertNotNull(domain);
    assertEquals("dc.corp.com", domain);
  }

  public void testGetDomainAD() throws NamingException {
    setupActiveDirectoryConfig(SSLSupport.NO_SSL);
    String domain = ldapClient.getDomain(AD_SAMNECN_DN);
    assertEquals("ENT-QA-D2", domain);
    assertEquals("ENT-QA-D2", ldapClient.getDomain(AD_SAMNECN_DN));
  }

  public void testGetDomainCached() throws NamingException {
    setupActiveDirectoryConfig(SSLSupport.NO_SSL);
    String domain1 = ldapClient.getDomain(AD_SAMNECN_DN);
    // we set incorrect password on the connection to make sure the request
    // to LDAP server would fail
    ldapClient.setAnonBindIdentity("invalid", "invalid");
    try {
      String domain2 = ldapClient.getDomain(AD_SAMNECN_DN);
      assertEquals(domain1, domain2);
    } catch (AuthenticationException e) {
      fail("The domain conversion from dn to netbiosname was not cached");
    }
  }

  public void testGetADProperty() throws NamingException {
    setupActiveDirectoryConfig(SSLSupport.NO_SSL);
    assertEquals("ENT-QA-D2",
        ldapClient.getADProperty("(ncName=" + AD_ROOT_BASE_DN + ")", "nETBIOSName"));
    assertEquals("ent-qa-d2.corp.google.com",
        ldapClient.getADProperty("(nETBIOSName=ent-qa-d2)", "dnsRoot"));
  }

  public void testGetCNFromDN() {
    String cn =  LDAPClient.getCNFromDN("cn=foo,ou=dc,dc=bar,dc=com");
    assertEquals("foo", cn);
    assertNull(LDAPClient.getCNFromDN(null));
    assertNull(LDAPClient.getCNFromDN(""));
    assertNull(LDAPClient.getCNFromDN("asdf"));
    assertNull(LDAPClient.getCNFromDN("uid=binzie,ou=engineer,dc=corp.google,dc=com"));
  }
}
