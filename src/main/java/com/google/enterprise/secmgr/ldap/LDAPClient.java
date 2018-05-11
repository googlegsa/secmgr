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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.enterprise.ldap.LDAPConfig;
import com.google.enterprise.ldap.LDAPConstants;
import com.google.enterprise.ldap.LDAPConstants.AuthMethod;
import com.google.enterprise.ldap.LDAPConstants.GroupResolutionFormat;
import com.google.enterprise.ldap.LDAPConstants.SSLSupport;
import com.google.enterprise.secmgr.ssl.SslContextFactory;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.AuthenticationException;
import javax.naming.ConfigurationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.SizeLimitExceededException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.SSLSocketFactory;

/**
 * This class encapsulates logic needed for authenticating against an LDAP
 * server. The implementation is based on JNDI.
 * An LDAPClient object is also capable of storing and retrieving it's
 * configuration parameters to/from a given Writer/Reader object.
 */
public class LDAPClient {
  
  private static final Logger logger =
      Logger.getLogger(LDAPClient.class.getName());

  // Following are the actual fields containing configuration information
  // for connecting to the LDAP server.
  private String hostport = null;  // <host>[:<port>] of LDAP server.
  // The default timeout is the same as in secmgr.config.AuthnMechanism.NO_TIME_LIMIT
  private int timeout = -1;        // connection and read timeout in milliseconds.
                                   // -1 means no timeout.
  private String base = "";        // component of DN common to all users.
  private String userSearchFilter = "";  // filter used to search for user.
  private String groupSearchFilter = ""; // filter used to find user's groups

  // Credentials used when detecting LDAP configuration parameters.
  // these should be empty if the server supports anonymous binding.
  private String anonBindDN = "";
  private String anonBindPassword = "";
  private String configurationNamingContext;
  private String dn;
  private boolean isActiveDirectory;
  private Map<String, String> nETBIOSCache = new HashMap<String, String>();
  
  private SSLSupport sslSupport = SSLSupport.NO_SSL;
  private AuthMethod authMethod = AuthMethod.SIMPLE;
  private GroupResolutionFormat groupResFormat = GroupResolutionFormat.CN;
  
  private SSLSocketFactory sslSocketFactory = null;
  
  public LDAPClient() {}

  public LDAPClient(LDAPConfig ldapConfig) {
    this.hostport = ldapConfig.getHostPort();
    this.base = ldapConfig.getBase();
    this.userSearchFilter = ldapConfig.getUserSearchFilter();
    this.groupSearchFilter = ldapConfig.getGroupSearchFilter();
    this.anonBindDN = ldapConfig.getAnonBindDN();
    this.anonBindPassword = ldapConfig.getAnonBindPassword();
    this.sslSupport = ldapConfig.getSSLSupportType();
    this.authMethod = ldapConfig.getAuthMethod();
    this.groupResFormat = ldapConfig.getGroupResolutionFormat();
  }
  
  public LDAPConfig getLdapConfig() {
    return new LDAPConfig(hostport, base, userSearchFilter, groupSearchFilter, 
        anonBindDN, anonBindPassword, sslSupport, authMethod, groupResFormat);
  }
  
  public void setLdapConfig(LDAPConfig ldapConfig) {
    this.hostport = ldapConfig.getHostPort();
    this.base = ldapConfig.getBase();
    this.userSearchFilter = ldapConfig.getUserSearchFilter();
    this.groupSearchFilter = ldapConfig.getGroupSearchFilter();
    this.anonBindDN = ldapConfig.getAnonBindDN();
    this.anonBindPassword = ldapConfig.getAnonBindPassword();
    this.sslSupport = ldapConfig.getSSLSupportType();
    this.authMethod = ldapConfig.getAuthMethod();
    this.groupResFormat = ldapConfig.getGroupResolutionFormat();
  }
  
  /**
   * Class to hold a name and DN.
   */
  public static class NameAndDomain {  
    private String name;
    private String domain;

    public NameAndDomain(String name, String domain) {
      this.name = name;
      this.domain = domain;
    }

    public String getName() {
      return name;
    }

    public String getDomain() {
      return domain;
    }

    public void setName(String name) {
      this.name = name;
    }

    @Override
    public boolean equals(Object object) {
      if (object == this) { return true; }
      if (!(object instanceof NameAndDomain)) { return false; }
      NameAndDomain nameAndDomain = (NameAndDomain) object;
      return Objects.equals(name, nameAndDomain.getName())
          && Objects.equals(domain, nameAndDomain.getDomain());
    }

    @Override
    public int hashCode() {
      return Objects.hash(name, domain);
    }
  }

  public void setSSLSocketFactory(SSLSocketFactory sslSocketFactory) {
    this.sslSocketFactory = sslSocketFactory;
  }
  
  /**
   * Attempts to automatically detect some configuration settings, by
   * connecting to the LDAP server.
   * We try and determine SSL support, base DN, user search filter and supported
   * authentication methods.
   * @return true if we successfully detected relevant settings.
   */
  public boolean detectSettings() {
    boolean res = detectSSLSupport(null);
    res &= detectBase(null);
    res &= detectUserSearchFilter(null);
    res &= detectGroupSearchFilter();
    res &= detectAuthMethods(null);
    return res;
  }

  /**
   * Attempts to automatically detect some configuration settings by
   * connecting to the LDAP server.
   * We try and validate the IP addr, determine SSL support,
   * base DN, user search filter and supported authentication methods.
   *
   * @return an object that describes the results of all steps.
   */
  public LDAPSettings detectSettingsVerbose() {
    // 'sb' will hold some "admin" or "developer" level trace about
    // the result of each step we perform. The intent is this'll be
    // exposed to the administrator in the AdminConsole, and for now
    // we believe it's essential to expose more info however it's
    // too hard to fully translate the info (as we need to expose things
    // like java exceptions...).
    StringBuilder sb = new StringBuilder();
    LDAPSettings res = new LDAPSettings();

    // [1] DNS resolution
    if (hostport == null ||
        hostport.trim().equals("")) {
      res.setCanResolveHost(false);
      res.setCanResolveHostInfo("Host not specified");
    } else {
      String tmp = hostport;
      int colon = tmp.indexOf(':');
      String host;
      if (colon < 0) {
        host = tmp;
      } else {
        host = tmp.substring(0, colon);
      }
      try {
        InetAddress[] addrs = InetAddress.getAllByName(host);
        sb.setLength(0);
        append(sb, String.format("Good, can resolve '%s' to ", host));
        for (int i = 0; i < addrs.length; i++) {
          append(sb, addrs[i].toString() + " ");
        }
        res.setCanResolveHost(true);
        res.setCanResolveHostInfo(sb.toString());
      } catch (UnknownHostException e) {
        res.setCanResolveHost(false);
        res.setCanResolveHostInfo(String.format("Can't resolve '%s'", host));
      }
    }

    // TODO: Can we do a lower level LDAP "ping" here with
    // a simple LDAP bind?

    // [2] SSL
    sb.setLength(0);
    res.setSSLSupportDetected(detectSSLSupport(sb));
    res.setSSLSupportInfo(sb.toString());

    // [3] LDAP Base
    sb.setLength(0);
    res.setBaseDetected(detectBase(sb));
    res.setBaseInfo(sb.toString());

    // [4] Search filter
    sb.setLength(0);
    res.setUserSearchFilterDetected(detectUserSearchFilter(sb));
    res.setUserSearchFilterInfo(sb.toString());

    // [5] Auth methods
    sb.setLength(0);
    res.setAuthMethodsDetected(detectAuthMethods(sb));
    res.setAuthMethodsInfo(sb.toString());

    // There's no verbose option to this method for some reason, but
    // it should be done to preserve the semantics of the detectSettings()
    // function.
    detectGroupSearchFilter();

    return res;
  }

  /**
   * Attempts to automatically detect the group search filter by connecting
   * to the LDAP server.  This method is kept separate from detectSettings
   * for backwards compatibility, since not all LDAP implementations previously
   * supported by this module are supported by group filter detection.
   * @return true if we successfully detected the filter
   */
  public boolean detectGroupSearchFilter() {
    groupSearchFilter = "";
    StringBuilder builder = new StringBuilder();
    try {
      String foundFilter = getSearchFilter(LDAPConstants.groupSearchFilters, builder);
      if (foundFilter != null) {
        // Add the nested lookup operator if we're using AD.
        // We don't do this during detection because using this operator with
        // a wildcard causes a PartialResultException to occur, which makes
        // sense because you shouldn't be able to do a nested lookup on a
        // wildcard.
        if (foundFilter.equals(LDAPConstants.activeDirectoryGroupSearchFilter)) {
          foundFilter = foundFilter.replaceAll("=", LDAPConstants.NESTED_LOOKUP_OPERATOR);
        }
        groupSearchFilter = foundFilter;
      }
    } catch (NamingException e) {
      logger.log(Level.SEVERE, "Exception while trying to detect search filter: "
          + builder.toString(), e);
    }
    if (!Strings.isNullOrEmpty((groupSearchFilter))) {
      logger.info("Decided to use group search filter: " + groupSearchFilter);
      logger.info("Debug info: " + builder.toString());
    } else {
      logger.info("Failed to detect group search filter: " + builder.toString());
    }

    return !Strings.isNullOrEmpty((groupSearchFilter));
  }

  /**
   * Authenticate user given username and password.
   * @param username the user name to lookup.
   * @param password the user password.
   * @return the full user DN on success, null on failure.
   * @throws javax.naming.ConfigurationException on any configuration failure.
   * @throws NamingException if one of the underlying LDAP
   * calls (connect(), eg) throws it
   */
  public String authenticate(String username, String password)
      throws NamingException {
    if (Strings.isNullOrEmpty(base)) {
      logger.severe("Can not authenticate users without base DN!");
      throw new ConfigurationException("LDAP Search Base empty");
    }
    if (Strings.isNullOrEmpty(userSearchFilter)) {
      logger.severe("Can not authenticate users without search filter!");
      throw new ConfigurationException("User Search Filter empty");
    }
    if (Strings.isNullOrEmpty(username)) {
      logger.severe("Can not authenticate empty user name!");
      throw new ConfigurationException("Username empty");
    }
    if (Strings.isNullOrEmpty(password)) {
      logger.severe("Can not authenticate empty password!");
      throw new ConfigurationException("Password empty");
    }

    DirContext ctx = connect();  // using "anon" or search-only binding.

    Set<NameAndDomain> distNames = findDNs(ctx, userSearchFilter, username);
    for (NameAndDomain distName : distNames) {
      String name = distName.getName();
      if (!name.toLowerCase().contains(base.toLowerCase())) {
        name = name + "," + base;
      }
      ctx.addToEnvironment(Context.SECURITY_AUTHENTICATION, "simple");
      ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, name);
      ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
      logger.fine("Trying to authenticate: " + username +
               " Using DN: " + name);

      // we need to try an LDAP operation. we try an empty search.
      try {
        testContext(ctx);  // just to try something.
        ctx.close();
        return name;  // success.
      } catch (AuthenticationException e) {
        // wrong password, may just be wrong user (different DN).
      }
    }
    ctx.close();
    logger.info("Failed to authenticate " + username);
    return null;  // authentication failed.
  }

  /**
   * Returns full DN for a user given the provided CN username.
   * @param username the user name to lookup.
   * @return the full user DN on success, null on failure.
   * @throws javax.naming.ConfigurationException on any configuration failure.
   * @throws NamingException if one of the underlying LDAP
   * calls (connect(), eg) throws it
   */
  public String getUserDN(String username)
      throws NamingException {
    if (Strings.isNullOrEmpty(base)) {
      logger.severe("Can not authenticate users without base DN!");
      throw new ConfigurationException("LDAP Search Base empty");
    }
    if (Strings.isNullOrEmpty(userSearchFilter)) {
      logger.severe("Can not find user's DN without search filter!");
      throw new ConfigurationException("User Search Filter empty");
    }
    if (Strings.isNullOrEmpty(username)) {
      logger.severe("Can not authenticate empty user name!");
      throw new ConfigurationException("Username empty");
    }

    DirContext ctx = connect();  // using "anon" or search-only binding.
    NameAndDomain distName = null;
    Set<NameAndDomain> distNames = findDNs(ctx, userSearchFilter, username);
    if (distNames != null && !distNames.isEmpty()) {
      distName = Iterables.get(distNames, 0);
      if (!distName.getName().toLowerCase().contains(base.toLowerCase())) {
        distName.setName(distName.getName() + "," + base);
      }
      logger.info("Found DN for user " + username + ": " + distName.getName());
    }

    ctx.close();
    logger.info("username " + username + " - getUserDN  - " + distName);
    return (distName == null) ? null : distName.getName();  // return DN or null
  }

  /**
   * Retrieves a list of group names to which a user belongs.
   * Must first have a groupSearchFilter setup, either by calling
   * detectGroupSearchFilter() or setGroupSearchFilter(filter).
   * @param username the username to lookup
   * @param dn the fully qualified dn for that username
   * @return a list of NameandDomain to which the user belongs;
   *           may be empty, but never null
   * @throws ConfigurationException on any configuration error
   * @throws NamingException if one of the underlying LDAP
   * calls (connect(), eg) throws it
   */
  public Set<NameAndDomain> getGroupsWithUser(String username, String dn)
      throws NamingException {
    if (Strings.isNullOrEmpty(base)) {
      logger.severe("Can not retrieve user groups without base DN!");
      throw new ConfigurationException("LDAP Search Base empty");
    }
    if (Strings.isNullOrEmpty(groupSearchFilter)) {
      logger.severe("Can not retrieve user groups without search filter!");
      throw new ConfigurationException("Group Search Filter empty");
    }
    if (Strings.isNullOrEmpty(username)) {
      logger.severe("Can not retrieve groups for empty user name!");
      throw new ConfigurationException("Username empty");
    }

    DirContext ctx = connect();

    Set<NameAndDomain> distNames = null;
    if (groupResFormat == GroupResolutionFormat.SAM_ACCOUNT_NAME) {
      distNames = findDNs(ctx, groupSearchFilter, username, dn, true,
          Lists.newArrayList(LDAPConstants.ATTRIBUTE_SAM_ACCOUNT_NAME), 
          LDAPConstants.ATTRIBUTE_SAM_ACCOUNT_NAME);
    } else {
      distNames = findDNs(ctx, groupSearchFilter, username, dn, true);
    }
    ctx.close();
    if (groupResFormat != GroupResolutionFormat.CN) {
      logger.fine("Groups - " + distNames);     
      return distNames;
    }
    Set<NameAndDomain> cnDistNames = getCNfromDN(distNames);
    logger.fine    ("Groups - " + cnDistNames);
    return cnDistNames;
  }

  private Set<NameAndDomain> getCNfromDN(Set<NameAndDomain>distNames) {
    Set<NameAndDomain> cnDistNames = Sets.newHashSet();
    for (NameAndDomain distName : distNames) {
      String cn = getCNFromDN(distName.getName());
      if (cn != null) {
        cnDistNames.add(new NameAndDomain(cn, distName.getDomain()));
      }
    }
    return cnDistNames;
  }

  /**
   * Extracts CN attribute from a given DN.
   */
  public static String getCNFromDN(String dn) {
    if (Strings.isNullOrEmpty(dn)) {
      return null;
    } 
    int pre = dn.toLowerCase().indexOf("cn=");
    int post = dn.indexOf(",", pre);
    if (pre == -1) {
      return null;
    }
    String cn;
    if (post != -1) {
      // Here 3 is length of 'cn='.  We just want to add the
      // group name.
      cn = dn.substring(pre + 3, post);
    } else {
      cn = dn.substring(pre + 3);
    }
    return cn;
  }

  /**
   * Given a dn, it returns the domain.
   * E.g., DN: uid=xyz,ou=engineer,dc=abc.google,dc=com
   * it will return abc.google.com
   * 
   * @param dn the distinguished name
   * @return domain in the form abc.com, or null if the input was invalid or did
   * not contain the domain attribute
   * @throws NamingException 
   */
  public String getDomain(String dn) throws NamingException {
    if (Strings.isNullOrEmpty(dn)) {
      return null;
    }
    int hasDC = dn.toLowerCase().indexOf("dc=");
    if (hasDC > -1) {
      String domaindn = dn.substring(hasDC);
      String nETBIOSName = nETBIOSCache.get(domaindn);
      if (nETBIOSName != null) {
        logger.fine(domaindn + " -> " + nETBIOSName + " from cache");
        return nETBIOSName;
      } else {
        nETBIOSName =
            getADProperty("(ncName=" + domaindn + ")", LDAPConstants.ATTRIBUTE_AD_NETBIOSNAME);
        if (nETBIOSName != null) {
          logger.fine("caching " + domaindn + " -> " + nETBIOSName);
          nETBIOSCache.put(domaindn, nETBIOSName);
          return nETBIOSName;
        }
      }
    }
    Iterable<String> str = Splitter.on(',').trimResults().omitEmptyStrings().split(dn);  
    StringBuilder strBuilder = new StringBuilder();
    for (String substr : str) {
      if (substr.startsWith("dc") || substr.startsWith("DC")) {
        strBuilder.append(substr.substring(3)).append(".");
      }
    }
    String strDomain = strBuilder.toString();
    if (Strings.isNullOrEmpty(strDomain)) {
      return null;
    }
    return strDomain.substring(0, strDomain.length() - 1);
  }

  /**
   * Retrieves a list of group names to which a user belongs.
   * It assumes the user DN is null.
   * Must first have a groupSearchFilter setup, either by calling
   * detectGroupSearchFilter() or setGroupSearchFilter(filter).
   * @param username the username to lookup
   * @return a list of NameAndDomain got the groups to which the user belongs;
   *           may be empty, but never null
   * @throws ConfigurationException on any configuration error
   * @throws NamingException if one of the underlying LDAP
   * calls (connect(), eg) throws it
   */
  public Set<NameAndDomain> getGroupsWithUser(String username)
      throws NamingException {
    return getGroupsWithUser(username, null);
  }

  public GroupResolutionFormat groupResolutionFormat() {
    return groupResFormat;
  }

  @VisibleForTesting
  public void setGroupResolutionFormat(GroupResolutionFormat format) {
    groupResFormat = format;
  }

  /** hostport is of the form <host>[:<port>] */
  public String hostPort() { return hostport; }

  /** hostport is of the form <host>[:<port>] */
  public void setHostPort(String hostPort) { this.hostport = hostPort.trim(); }

  /** @return true if host has not yet been set. */
  public boolean noHost() {
    return Strings.isNullOrEmpty(hostport);
  }

  public int timeout() { return timeout; }
  public void setTimeout(int timeout) { this.timeout = timeout; }

  public String base() { return base; }
  public void setBase(String base) { this.base = base.trim(); }


  public String userSearchFilter() { return userSearchFilter; }
  /**
   * Set the user search filter.
   * @param userSearchFilter the filter expression. This should contain the
   * substring %s which will be replaced by the user name when searching for
   * the full user DN.
   */
  public void setUserSearchFilter(String userSearchFilter) {
    this.userSearchFilter = userSearchFilter;
  }

  public String groupSearchFilter() { return groupSearchFilter; }
  /**
   * Set the user search filter.
   * @param groupSearchFilter the filter expression. This should contain the
   * substring %s which will be replaced by the user name when searching for
   * the full user DN.
   */
  public void setGroupSearchFilter(String groupSearchFilter) {
    this.groupSearchFilter = groupSearchFilter;
  }

  public SSLSupport sslSupportType() { return sslSupport; }
  public void setSSLSupportType(SSLSupport sslSupportType) {
    this.sslSupport = sslSupportType;
  }


  public AuthMethod supportedAuthMethods() { return authMethod; }
  public void setSupportedAuthMethods(AuthMethod supportedAuthMethods) {
    this.authMethod = supportedAuthMethods;
  }


  /**
   * Sets the credentials used for binding to the LDAP server for general
   * (non user specific) searches. For instance to get different DNs matching
   * same user name, or for identifying base DN.
   */
  public void setAnonBindIdentity(String dn,
                                  String password) {
    this.anonBindDN = dn;
    this.anonBindPassword = password;
  }
  public String anonBindDN()        { return anonBindDN; }
  public String anonBindPassword()  { return anonBindPassword; }


  /**
   * Append a string to a StringBuilder and make sure there's a newline
   * at the end.
   * @param sb the builder to add to
   * @param s the string to add
   */
  private static void append(StringBuilder sb, String s) {
    if (sb != null) {
      sb.append(s + "\n");
    }
  }

  /**
   * Attempt to detect base DN (name space). We do this by binding to the
   * LDAP server and finding the shortest root naming context.
   *
   * @param info is populated with trace about steps we perform and is destined
   * for the administrator
   *
   * @return true if we found what looks like the base DN.
   */
  protected boolean detectBase(StringBuilder info) {
    base = "";
    try {
      DirContext ctx = connect();
      // search for naming contexts:
      String[] matchAttrs = new String[1];
      matchAttrs[0] = LDAPConstants.baseDNAttribute;
      append(info, String.format("Trying base attribute: '%s'",  matchAttrs[0]));
      Attributes attrs = ctx.getAttributes("", matchAttrs);
      Attribute att = null;
      if (attrs != null) {
        att = attrs.get(LDAPConstants.baseDNAttribute);
      }
      if (att == null) {
        append(info, "Can't find root context");
        throw new NamingException("Unable to search root context for: " +
            LDAPConstants.baseDNAttribute);
      } else {
        append(info, "Good, I found a root context");
      }
      NamingEnumeration<?> names = att.getAll();
      // look for shortest naming context:
      while (names.hasMore()) {
        Object value = names.next();
        append(info, String.format("Found value '%s'", value));
        if ((value == null) || !(value instanceof String)) {
          if (value == null) {
            append(info, "No value");
          } else {
            append(info, "Wrong type: " +  value.getClass());
          }
          continue;  // what is this?
        }
        String name = (String) value;
        if (name.length() == 0) {
          append(info, "Value too short (0 chars)");
          continue;  // odd.
        }
        logger.fine("Considering base DN: " + name);
        // we just take shortest base DN, hoping it is most general:
        if ((base.length() == 0) || (name.length() < base.length())) {
          append(info, String.format("Picking '%s' as it's the shortest so far", name));
          base = name;
        } else {
          append(info, String.format("Not picking '%s' as it's not the shortest", name));
        }
      }
      ctx.close();
    } catch (NamingException e) {
      append(info, "Problem while trying to find the base: " + e);
      logger.log(Level.SEVERE, "Exception while trying to detect base", e);
    }

    if (!Strings.isNullOrEmpty(base)) {
      append(info, String.format("Using base: '%s'", base));
      logger.info("Good, decided to use base DN: " + base);
    } else {
      append(info, "Failed to detect base");
      logger.info("Failed to detect base DN.");
    }

    return !Strings.isNullOrEmpty(base);
  }


  /**
   * Attempt to detect user search filter. We search for user objects, using
   * a predefined list of common filters. We select the first one which
   * results in two or more users.
   *
   * @param info is populated with trace about steps we perform and is destined
   * for the administrator
   *
   * @return true if we managed to determine what looks like a good filter.
   */
  protected boolean detectUserSearchFilter(StringBuilder info) {
    userSearchFilter = "";

    try {
      String foundFilter = getSearchFilter(LDAPConstants.userSearchFilters, info);
      if (foundFilter != null) {
        userSearchFilter = foundFilter;
      }
    } catch (NamingException e) {
      append(info, "Problem while getting filter: " + e);
      logger.log(Level.SEVERE, "Exception while trying to detect search filter", e);
    }
    if (!Strings.isNullOrEmpty(userSearchFilter)) {
      logger.info("Decided to use user search fiter: " + userSearchFilter);
    } else {
      logger.info("Failed to detect user search filter.");
    }

    return !Strings.isNullOrEmpty(userSearchFilter);
  }

  /**
   * @param info is populated with trace about steps we perform and is destined
   * for the administrator
   */
  protected String getSearchFilter(String[] allFilters, StringBuilder info)
      throws NamingException {
    String foundFilter = null;
    DirContext ctx = connect();

    // search over whole subtree, do not return objects, do not return more
    // than one result.
    SearchControls controls = new SearchControls();
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    controls.setReturningObjFlag(false);
    controls.setReturningAttributes(new String[] {LDAPConstants.ATTRIBUTE_DN});
    controls.setCountLimit(1);  // find a filter returning at least 2.

    // loop over predefined filters searching for users:
    for (int i = 0; i < allFilters.length; ++i) {
      append(info, "Trying search filter: " + allFilters[i]);
      // use wild card as user name:
      String filter = replaceInFilter(allFilters[i], "%s", "*");
      // Use wild card as fully qualified user name as well.
      filter = replaceInFilter(filter, "%dn", "*");
      try {
        NamingEnumeration<SearchResult> answer = ctx.search(base, filter, controls);
        // just check to see if we got more than one user using this filter:
        // (can't find any other way to do this :(. ) It is a good thing
        // we only care if it is two or more...
        while (answer.hasMore()) {
          logger.info("answer: " + answer.next());
        }
        // TODO: Something very strange the way
        // SizeLimitExceededException below is the successful block.
      } catch (SizeLimitExceededException e) {
        append(info, "Good search filter: " + allFilters[i]);
        // this is good. We found at least two elements.
        foundFilter = allFilters[i];

        // break to ensure that we close the connection
        break;
      } catch (NamingException e) {
        append(info, "Bad search filter: " + allFilters[i] + ", Because: " + e.toString());
        // some problem with this filter, lets try the next one anyway
      }
    }
    ctx.close();
    if (foundFilter == null) {
      append(info, "Failing this step as no filter found that works with " +
             "wildcard ('*') search");
    } else {
      append(info, String.format("Good, filter '%s' found", foundFilter));
    }
    return foundFilter;
  }

  /**
   * Takes user SID as binary string, group RID as string and converts them to escaped hex
   * representation of LDAP search filter
   *
   * @param sid user binary SID
   * @param primaryGroupId primary group RID (guaranteed to be within user's domain)
   * @return string containing LDAP search filter for user's primary group
   */
  protected String getSearchFilterForPrimaryGroup(byte[] sid, String primaryGroupId) {
    long primaryGroup = Long.parseLong(primaryGroupId);
    
    // replace the last four bytes of user's SID with group RID
    sid[sid.length - 1] = (byte) ((primaryGroup >> 24) & 0xFF);
    sid[sid.length - 2] = (byte) ((primaryGroup >> 16) & 0xFF);
    sid[sid.length - 3] = (byte) ((primaryGroup >> 8) & 0xFF);
    sid[sid.length - 4] = (byte) (primaryGroup & 0xFF);

    // format the SID as escaped hexa (i.e. \01\05\ff...)
    StringBuilder formatSid = new StringBuilder();

    for (int i = 0; i < sid.length; ++i) {
      int unsignedByte = sid[i] & 0xFF;
      // add zero padding for single digits
      if (unsignedByte < 16) {
        formatSid.append("\\0");
      } else {
        formatSid.append("\\");
      }
      formatSid.append(Integer.toHexString(unsignedByte));
    }

    return String.format(LDAPConstants.PRIMARY_GROUP_FILTER, formatSid.toString());
  }

  /**
   * Returns user's primary group
   *
   * @param ctx The ldap context.
   * @param userSid SID of the user in Active Directory.
   * @param primaryGroupId domain local ID of the primary group.
   * @param returnAttributes The list of desired return attributes from the search.
   * @param attributeName return attribute name for which the value will be returned
   *   from the search. 
   * @return NameAndDomain for the primary group.
   */
  protected NameAndDomain getPrimaryGroupForUser(DirContext ctx, byte[] userSid, 
      String primaryGroupId, List<String> returnAttributes, String attributeName) {
    List<String> newReturnAttributes = Lists.newArrayList(returnAttributes);
    newReturnAttributes.add(LDAPConstants.ATTRIBUTE_MEMBER_OF);
    if (userSid == null || primaryGroupId == null) {
      logger.log(Level.WARNING, "No user sid or primary group id");
      return null;
    }
    logger.fine("Getting primary group " + Arrays.toString(userSid) + " " + primaryGroupId);
    String primaryGroupDN = null;
    String primaryGroupName = null;

    SearchControls controls = new SearchControls();
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    String[] strArry = new String[newReturnAttributes.size()];
    controls.setReturningAttributes(newReturnAttributes.toArray(strArry));

    // Create the search filter
    String searchFilter = getSearchFilterForPrimaryGroup(userSid, primaryGroupId);
    NamingEnumeration<SearchResult> ldapResults = null;
    try {
      ldapResults = ctx.search(base, searchFilter, controls);
      SearchResult searchResult = ldapResults.next();
      primaryGroupDN = searchResult.getNameInNamespace();
      Attribute adDn = searchResult.getAttributes().get(attributeName);
      primaryGroupName = (adDn == null ? searchResult.getName() : adDn.get().toString());
    } catch (NamingException ne) {
      logger.log(Level.WARNING, "Failed to retrieve primary group with SID: ["
          + searchFilter + "]", ne);
    } finally {
      try {
        if (null != ldapResults) {
          ldapResults.close();
        }
      } catch (NamingException e) {
        logger.log(Level.WARNING, "Exception during clean up of ldap results.", e);
      }
    }
    logger.fine("Got primary group name :" + primaryGroupName);
    logger.fine("Got primary group DN :" + primaryGroupDN);
    return new NameAndDomain(primaryGroupName, primaryGroupDN);
  }

  /**
   * Returns user's primary group
   *
   * @param ctx The ldap context.
   * @param dn distinguishedName in Active Directory.
   * @return NameAndDomain of the primary group.
   * @throws javax.naming.NamingException
   */
  protected NameAndDomain getPrimaryGroup(DirContext ctx, String dn, 
      List<String> returnAttributes, String attributeName) throws NamingException {
    // This search can't be combined with the all groups search because of
    // different filters!
    String filter = String.format(LDAPConstants.DIRECT_GROUPS_FILTER, dn)
        .replaceAll("\\\\", "\\\\\\\\");

    SearchControls controls = new SearchControls();
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    controls.setReturningAttributes(new String[] {LDAPConstants.ATTRIBUTE_MEMBER_OF,
        LDAPConstants.ATTRIBUTE_PRIMARY_GROUP_ID,
        LDAPConstants.ATTRIBUTE_OBJECTSID});
    controls.setReturningObjFlag(false);

    NamingEnumeration<SearchResult> answer =
        ctx.search(base, filter, controls);
    byte[] userSid = null;
    String primaryGroupId = null;

    try {
      while (answer.hasMore()) {
        SearchResult result = answer.next();
        Attributes attrs = result.getAttributes();
        if (attrs == null) {
          logger.warning("No attribute for " + dn);
          continue;
        }

        Attribute attr = attrs.get(LDAPConstants.ATTRIBUTE_PRIMARY_GROUP_ID);
        if (attr != null) {
          logger.fine("primary group " + attr.get().toString());
          primaryGroupId = attr.get().toString();
        }

        attr = attrs.get(LDAPConstants.ATTRIBUTE_OBJECTSID);
        if (attr != null) {
          logger.fine("sid " + attr.get().toString());
          userSid = (byte[]) attr.get();
        }
      }

    } catch (NamingException e) {
      // we ignore exceptions while collecting results. this may
      // indicate partial results, just return what we have collected so
      // far.
    } finally {
      try {
        if (null != answer) {
          answer.close();
        }
      } catch (NamingException e) {
        logger.log(Level.WARNING, "Exception during clean up of ldap results.", e);
      }
    }

    return getPrimaryGroupForUser(ctx, userSid, primaryGroupId, returnAttributes, attributeName);
  }

  /**
   * Attempt to detect SSL support. Try to connect over SSL, see what happens.
   *
   * @param info is populated with trace about steps we perform and is destined
   * for the administrator
   *
   * @return always returns true for now as worst case we just assume SSL isn't needed
   */
  protected boolean detectSSLSupport(StringBuilder info) {
    // first try Start TLS:
    sslSupport = SSLSupport.START_TLS;
    append(info, "Trying TLS transport protocol");
    try {
      DirContext ctx = connect();
      // test context (this tests search user credentials if they were set):
      testContext(ctx);
      ctx.close();
      logger.info("LDAP server supports Start TLS");
      append(info, "Good, TLS supported");
      return true;
    } catch (NamingException e) {
      // guess it does not support Start TLS.
      logger.info("LDAP server does not support Start TLS (" + e.toString() + ")");
      append(info, "TLS not supported because: " + e);
    }

    // try with LDAP over TLS:
    sslSupport = SSLSupport.TLS_SSL;
    append(info, "Trying TLS/SSL transport protocol");
    try {
      DirContext ctx = connect();
      // we have to do something with context here to force a handshake:
      testContext(ctx);
      ctx.close();
      logger.info("LDAP server supports SSL");
      append(info, "Good, SSL supported");
      return true;
    } catch (NamingException e) {
      // guess it does not support SSL.
      logger.info("LDAP server does not support SSL (" + e.toString() + ")");
      append(info, "SSL not supported because: " + e);
    }

    // No SSL support was detected.
    append(info, "No TLS or TLS/SSL support detected so will assume SSL isn't " +
           "needed thus this stage passes");
    sslSupport = SSLSupport.NO_SSL;
    return true;
  }


  /**
   * Attempt to detect supported authentication methods. This method is
   * not implemented yet.
   *
   * @param info is populated with trace about steps we perform and is destined
   * for the administrator
   *
   * @return always returns true for now.
   */
  private boolean detectAuthMethods(StringBuilder info) {
    authMethod = AuthMethod.SIMPLE;  // not yet implemented.
    return true;
  }

  /**
   * Connect to LDAP server using anonymous bind, or admin specified
   * credentials. This is good, for general searches, not tied to specific user.
   * Used when trying to get all unique DNs with same username. Also used
   * by detection methods.
   * @return DirContext object on success.
   * @throws javax.naming.NamingException
   */
  private DirContext connect() throws NamingException {
    Hashtable<String, String> env = new Hashtable<String, String>(11);
    env.put(Context.INITIAL_CONTEXT_FACTORY,
        "com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL, "ldap://" + hostport + "/");
    if (timeout > 0) {
      env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(timeout));
      env.put("com.sun.jndi.ldap.read.timeout", String.valueOf(timeout));
    }

    if (sslSupport == SSLSupport.TLS_SSL) {
      if (sslSocketFactory == null) {
        // we use an Enterprise specific socket factory, so we can read CAs
        // and CRLs from our keystores.
        env.put("java.naming.ldap.factory.socket",
                "com.google.enterprise.secmgr.ssl.SslSocketFactory");
      } else {
        env.put("java.naming.ldap.factory.socket",
            sslSocketFactory.getClass().getCanonicalName());
      }
      env.put(Context.SECURITY_PROTOCOL, "ssl");
    }

    LdapContext ctx = new InitialLdapContext(env, null);

    if (sslSupport == SSLSupport.START_TLS) {
      // Start TLS
      StartTlsResponse tls =
        (StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());
      try {
        if (sslSocketFactory == null) {
          sslSocketFactory = SslContextFactory.getSocketFactory();
        }
        tls.negotiate(sslSocketFactory);
      } catch (IOException e) {
        NamingException ne =
          new NamingException("Failed to negotiate Start TLS");
        ne.setRootCause(e);
        throw ne;
      }
    }

    if ((anonBindDN != null) && (anonBindDN.length() > 0)) {
      ctx.addToEnvironment(Context.SECURITY_AUTHENTICATION, "simple");
      ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, anonBindDN);
      ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, anonBindPassword);
    }
    
    Attributes attributes = ctx.getAttributes("");
    isActiveDirectory =
        attributes.get(LDAPConstants.ATTR_DSSERVICENAME) != null;
    if (isActiveDirectory) {
      dn = attributes.get(
          LDAPConstants.ATTRIBUTE_AD_DEFAULTNAMINGCONTEXT).get(0).toString();
      configurationNamingContext = attributes.get(
          LDAPConstants.ATTRIBUTE_AD_CONFIGURATIONNAMINGCONTEXT).get(0).toString();
    }
    return ctx;
  }

  /**
   * Find list of all DNs which share specified user ID (user name), through
   * a given filter.
   * @param ctx The ldap context.
   * @param filter The filter to be using for this search
   * @param uid The user name.
   * @param dn The fully-qualified DN for the user.
   * @param ofGroups Whether to lookup groups or not.
   * @return A set of NameAndDomain found (may be empty, never null).
   * @throws javax.naming.NamingException
   */
  private Set<NameAndDomain> findDNs(DirContext ctx, String filter, String uid,
      String dn, boolean ofGroups) throws NamingException {
    return findDNs(ctx, filter, uid, dn, ofGroups, Lists.newArrayList(
        LDAPConstants.ATTRIBUTE_DN, LDAPConstants.ATTRIBUTE_AD_DN), 
        LDAPConstants.ATTRIBUTE_AD_DN);
  }

  /**
   * Find list of all DNs which share specified user ID (user name), through
   * a given filter.
   * @param ctx The ldap context.
   * @param filter The filter to be using for this search
   * @param uid The user name.
   * @param dn The fully-qualified DN for the user.
   * @param ofGroups Whether to lookup groups or not.
   * @param returnAttributes The list of desired return attributes from the search.
   * @param attributeName return attribute name for which the value will be returned
   *   from the search.
   * @return A set NameAndDomain of all DNs found (may be empty, never null).
   * @throws javax.naming.NamingException
   */
  private Set<NameAndDomain> findDNs(DirContext ctx, String filter, String uid,
      String dn, boolean ofGroups, List<String> returnAttributes, String attributeName)
      throws NamingException {
    Set<NameAndDomain> distNames = Sets.newHashSet();
    String actualFilter = replaceInFilter(filter, "%s", uid);
    actualFilter = replaceInFilter(actualFilter, "%dn", dn);

    // It is necessary to double-escape the string for the search.
    actualFilter = actualFilter.replaceAll("\\\\", "\\\\\\\\");

    SearchControls controls = new SearchControls();
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    String[] strArry = new String[returnAttributes.size()];
    controls.setReturningAttributes(returnAttributes.toArray(strArry));
    controls.setReturningObjFlag(false);

    NamingEnumeration<SearchResult> answer =
        ctx.search(base, actualFilter, controls);
    try {
      try {
        String fullDN;
        while (answer.hasMore()) {
          SearchResult result = answer.next();
          fullDN = result.getNameInNamespace();
          logger.fine("DN - " + fullDN);
          Attributes attrs = result.getAttributes();
          if (attrs == null) {
            continue;
          }
          // Active directory results will contain an attribute with the
          // full DN, so if possible we return that result.
          Attribute adDn = result.getAttributes().get(attributeName);

          String attributeValue = adDn == null ? result.getName() : adDn.get().toString();
          logger.fine("Attribute value - " + attributeValue);
          distNames.add(new NameAndDomain(attributeValue, fullDN));
        }
      } catch (PartialResultException e) {
        // If AD is configured with root search base, hasMore() will throw
        // exception since we do not follow referrals. Ignore and continue.
      }

      // In active directory, need to get primary group separately.
      if (isActiveDirectory && ofGroups) {
        NameAndDomain primaryGroup = 
            getPrimaryGroup(ctx, dn, returnAttributes, attributeName);
        if (primaryGroup != null) {
          distNames.add(primaryGroup);
        }
      }
    } catch (NamingException e) {
      // we ignore exceptions while collecting results. this may
      // indicate partial results, just return what we have collected so
      // far.
    } finally {
      try {
        if (null != answer) {
          answer.close();
        }
      } catch (NamingException e) {
        logger.log(Level.WARNING, "Exception during clean up of ldap results.", e);
      }
    }

    return distNames;
  }

  /**
   * Find list of all DNs which share specified user ID (user name), through
   * a given filter.
   * @param ctx The ldap context.
   * @param filter The filter to be using for this search
   * @param uid The user name.
   * @return A set NameAndDomain of all DNs found (may be empty, never null).
   * @throws javax.naming.NamingException
   */
  private Set<NameAndDomain> findDNs(DirContext ctx, String filter, String uid)
      throws NamingException {
    return findDNs(ctx, filter, uid, "", false);
  }

  /**
   * Test a given context by doing a null - lookup.
   * @param ctx the context to test.
   * @throws javax.naming.NamingException if lookup fails.
   */
  private void testContext(DirContext ctx) throws NamingException {
    // TODO can we come up with something better than this?
    // we do a dummy request for attribute on root context. 
    String[] matchAttrs = new String[0];  // empty array means return no atts.
    ctx.getAttributes("", matchAttrs);
  }

  /**
   * Returns the email address of a given user. It should not happen
   * but, if more than one user shows up in our search filter, then we
   * return the mail address of the first user.
   * @param uid The user name.
   * @throws javax.naming.NamingException if lookup fails.
   */
  public String getMail(String uid) throws NamingException {
    String searchFilter = replaceInFilter(userSearchFilter, "%s", uid);
    SearchControls controls = new SearchControls();
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    controls.setReturningAttributes(new String[] {LDAPConstants.ATTRIBUTE_DN, 
        LDAPConstants.ATTRIBUTE_MAIL});
    controls.setReturningObjFlag(false);

    // Use anonymous bindings.
    DirContext ctx = connect();
    int count = 0;
    NamingEnumeration<SearchResult> answer =
        ctx.search(base, searchFilter, controls);
    while (answer.hasMore()) {
      count++;
      Attribute mailAttr = answer.next().getAttributes().get(LDAPConstants.ATTRIBUTE_MAIL);
      if (mailAttr != null && mailAttr.get() != null) {
        if (count > 1) {
          logger.warning("LDAP returned more than 1 entry. [count=" + count
                      + "] for the search filter=" + searchFilter);
        }
        return mailAttr.get().toString();
      }
    }

    return null;
  }

  /**
   * Replace all occurrences of <target> in <filter> with the specified
   * <replacement>.
   * @param filter the filter expression.
   * @param target the string to be replaced in the filter
   * @param replacement the replacement string
   * @return the original filter if any arguments are empty or null and
   * result of filter.replace(target, replacement) otherwise
   */
  protected String replaceInFilter(String filter, String target,
      String replacement) {
    if (Strings.isNullOrEmpty(replacement) || Strings.isNullOrEmpty(target) ||
        Strings.isNullOrEmpty(filter)) {
      return filter;
    }
    return filter.replace(target, replacement);
  }

  /**
   * Retrieves domain property name from configuration context of the Active Directory.
   * @return netbios domain
   * @throws NamingException
   */
  public String getADProperty(String filter, String attribute) throws NamingException {
    SearchControls controls = new SearchControls();
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
    controls.setReturningAttributes(new String[] {attribute});
    controls.setReturningObjFlag(false);
    DirContext ctx = connect();
    if (!isActiveDirectory) {
      return null;
    }
    try {
      NamingEnumeration<SearchResult> ldapResults =
          ctx.search(configurationNamingContext, filter, controls);
      if (!ldapResults.hasMore()) {
        return null;
      }
      SearchResult sr = ldapResults.next();
      Attributes attrs = sr.getAttributes();
      Attribute at = attrs.get(attribute);
      if (at != null) {
        return (String) attrs.get(attribute).get(0);
      }
    } catch (NamingException e) {
        logger.log(Level.WARNING,
            "Failed retrieving " + filter + " from AD server", e);
    }
    return null;
  }
  
  /** This method is only used for quick tests.
   * You pass in a host name on the cmd line and an
   * optional user name (e.g. "LDAPClient ldap.corp")
   * and it runs thru the LDAP detection code and prints out
   * what we know about the host and user (if present).
   */
  public static void main(String[] args) throws Throwable {
    LDAPClient client = new LDAPClient();
    PrintStream o = System.out;
    int numArgs = args.length;

    if (numArgs < 1 || numArgs > 2) {
      System.err.println("Wrong # of args - I need:");
      System.err.println("\tHOST [USER]");
      System.exit(1);
    }

    client.setHostPort(args[0]);
    o.println("detectSettings: " + client.detectSettings());
    o.println("detectGroupSearchFilter: " + client.detectGroupSearchFilter());

    o.println();

    o.println("SSL Type           : " + client.sslSupportType());
    o.println("Client Base        : " + client.base());
    o.println("User Search Filter : " + client.userSearchFilter());
    o.println("Group Search Fitler: " + client.groupSearchFilter());

    if (numArgs >= 2) {
      String user = args[1];
      o.println("Email              : " + client.getMail(user));
      o.println("Groups:");
      for (NameAndDomain group : client.getGroupsWithUser(user)) {
        o.println("\t" + group);
      }
    }
    System.exit(0);
  }

  /**
   * Gather discrete information about result of all steps
   * we perform during the process to detect the right LDAP
   * settings. We are essentially a dumb container object
   * with the exception of {@link #toVerboseString} which has
   * a little bit of logic to format an inteligible description
   * of our contents.
   */
  public static class LDAPSettings {
    private boolean canResolveHost;
    private boolean sslSupportDetected;
    private boolean baseDetected;
    private boolean userSearchFilterDetected;
    private boolean authMethodsDetected;

    private String canResolveHostInfo;
    private String baseInfo;
    private String sslSupportInfo;
    private String userSearchFilterInfo;
    private String authMethodsInfo;

    @VisibleForTesting
    public LDAPSettings() {
    }

    public void setCanResolveHostInfo(String s) {
      canResolveHostInfo = s;
    }

    public void setBaseInfo(String s) {
      baseInfo = s;
    }

    public void setSSLSupportInfo(String s) {
      sslSupportInfo = s;
    }

    public void setUserSearchFilterInfo(String s) {
      userSearchFilterInfo = s;
    }

    public void setAuthMethodsInfo(String s) {
      authMethodsInfo = s;
    }

    public String getCanResolveHostInfo() {
      return canResolveHostInfo;
    }

    public String getBaseInfo() {
      return baseInfo;
    }

    public String getSSLSupportInfo() {
      return sslSupportInfo;
    }

    public String getUserSearchFilterInfo() {
      return userSearchFilterInfo;
    }

    public String getAuthMethodsInfo() {
      return authMethodsInfo;
    }

    public void setCanResolveHost(boolean val) {
      canResolveHost = val;
    }

    public void setSSLSupportDetected(boolean val) {
      sslSupportDetected = val;
    }

    public void setBaseDetected(boolean val) {
      baseDetected = val;
    }

    public void setUserSearchFilterDetected(boolean val) {
      userSearchFilterDetected = val;
    }

    public void setAuthMethodsDetected(boolean val) {
      authMethodsDetected = val;
    }

    public boolean isSSLSupportDetected() {
      return sslSupportDetected;
    }

    public boolean isCanResolveHost() {
      return canResolveHost;
    }

    public boolean isBaseDetected() {
      return baseDetected;
    }

    public boolean isUserSearchFilterDetected() {
      return userSearchFilterDetected;
    }

    public boolean isAuthMethodsDetected() {
      return authMethodsDetected;
    }

    public boolean detectedAllSettings() {
      return sslSupportDetected &&
          baseDetected &&
          userSearchFilterDetected &&
          authMethodsDetected;
    }

    /**
     * For formating the descriptions convert a boolean into
     * a word indicating the result of the step.
     */
    private static String passFail(boolean succeeded) {
      if (succeeded) {
        return "passed";
      } else {
        return "failed";
      }
    }

    /**
     * Form a string that describes all steps that we represent.
     *
     * @param allSteps if true means show the sequence of steps even after one
     * fails, while if false then we show the minimal set of steps i.e. we stop
     * at the first failure.
     *
     * @return the steps we took to determine the configuration of the LDAP
     * server
     */
    public String toVerboseString(boolean allSteps) {
      StringBuilder sb = new StringBuilder(256);
      append(sb, String.format("[1] Low level DNS host resolution %s.",
                               passFail(canResolveHost)));
      append(sb, canResolveHostInfo);
      if (!allSteps && !canResolveHost) {
        return sb.toString();
      }

      append(sb, String.format("[2] SSL Detection %s.",
                               passFail(sslSupportDetected)));
      append(sb, sslSupportInfo);
      if (!allSteps && !sslSupportDetected) {
        return sb.toString();
      }

      append(sb, String.format("[3] Base detection %s.",
                               passFail(baseDetected)));
      append(sb, baseInfo);
      if (!allSteps && !baseDetected) {
        return sb.toString();
      }

      append(sb, String.format("[4] User search filter %s.",
                               passFail(userSearchFilterDetected)));
      append(sb, userSearchFilterInfo);
      if (!allSteps && !userSearchFilterDetected) {
        return sb.toString();
      }

      append(sb, "[5] Auth method detection %s." +
             passFail(authMethodsDetected));
      append(sb, authMethodsInfo);
      return sb.toString();
    }
  }
}
