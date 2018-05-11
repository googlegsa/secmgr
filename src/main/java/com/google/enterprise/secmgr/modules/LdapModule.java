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

package com.google.enterprise.secmgr.modules;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableSet;
import com.google.enterprise.ldap.LDAPConstants;
import com.google.enterprise.ldap.LDAPConstants.AuthMethod;
import com.google.enterprise.ldap.LDAPConstants.GroupResolutionFormat;
import com.google.enterprise.ldap.LDAPConstants.SSLSupport;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.logmanager.LogClientParameters;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnModule;
import com.google.enterprise.secmgr.authncontroller.AuthnModuleException;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.config.AuthnMechLdap;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.ldap.LDAPClient;
import com.google.enterprise.secmgr.ldap.LDAPClient.NameAndDomain;
import com.google.inject.Singleton;

import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;
import javax.naming.NamingException;

/**
 * LDAP Connector.
 */
@Singleton
@Immutable
public final class LdapModule implements AuthnModule {
  /**
   * Implicit group "Everyone" in Active Directory.
   */
  public static final String IMPLICIT_EVERYONE = "Everyone";

  private static final Logger logger = Logger.getLogger(LdapModule.class.getName());
  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());

  @GuardedBy("this")
  private LDAPClient ldapClientForTesting;

  @SuppressWarnings("unused")
  @VisibleForTesting
  @Inject
  LdapModule() {
    ldapClientForTesting = null;
  }

  @VisibleForTesting
  LdapModule(LDAPClient client) {
    ldapClientForTesting = client;
  }

  @Override
  public boolean willHandle(SessionView view) {
    return view.getMechanism() instanceof AuthnMechLdap;
  }

  @Override
  public AuthnSessionState authenticate(SessionView view)
      throws AuthnModuleException {
    AuthnMechLdap mech = AuthnMechLdap.class.cast(view.getMechanism());
    String namespace = view.getCredentialGroup().getName();
    // Short-circuit if we don't have anything to do.
    if (!mech.isEnableAuthn() && !mech.isEnableGroupLookup()) {
      return AuthnSessionState.empty();
    }

    // All other combinations of enabled features require work by client.
    LDAPClient ldapClient = getLDAPClient(mech);
    AuthnPrincipal principal = view.getPrincipal();
    AuthnController.check(principal != null, "Missing principal");
    AuthnPrincipal newPrincipal = principal;
    long expirationTime = Verification.EXPIRES_AFTER_REQUEST;
    ImmutableSet.Builder<Credential> builder = ImmutableSet.builder();

    // Perform LDAP authentication of user if enabled.
    String idToLog = LogClientParameters.recordUsernames
        ? principal.getName() : LogClientParameters.ID_NOT_LOGGED;
    if (mech.isEnableAuthn()) {
      gsaLogger.info(view.getRequestId(),
          "LDAP Auth: authenticating user " + idToLog);
      CredPassword password = view.getPasswordCredential();
      if (password != null) {
        String dn;
        try {
          dn = ldapClient.authenticate(principal.getName(), password.getText());
          if (dn != null) {
            String userDomain = ldapClient.getDomain(dn);
            newPrincipal = AuthnPrincipal.make(principal.getName(), namespace, userDomain);
          }
        } catch (NamingException e) {
          logger.log(Level.WARNING, view.logMessage("Error authenticating %s: ",
              idToLog), e);
          gsaLogger.info(view.getRequestId(),
              "LDAP Auth: authentication error for user " + idToLog);
          gsaLogger.info(view.getRequestId(), "LDAP Auth: " + e.getMessage());
          return AuthnSessionState.empty();
        }
        if (dn == null) {
          builder.add(principal);
          builder.add(password);
          gsaLogger.info(view.getRequestId(),
            "LDAP Auth: authentication failed for user " + idToLog);
          return AuthnSessionState.of(view.getAuthority(), Verification.refuted(builder.build()));
        }
        builder.add(newPrincipal);
        builder.add(password);
        expirationTime = view.getConfiguredExpirationTime();
      } else {
        AuthnController.check(view.hasVerifiedPrincipal(), "Credential not verified");
        // if authenicate is called without password, it means we should rewrite the domain
        // for current principal with nETBIOSName
        try {
          String nETBIOSName = ldapClient.getADProperty(
              "(&(dnsRoot=" + principal.getDomain() + ")(nETBIOSName=*))",
              LDAPConstants.ATTRIBUTE_AD_NETBIOSNAME);
          if (nETBIOSName != null) {
            gsaLogger.info(view.getRequestId(), "Rewriting dnsRoot [" + principal.getDomain()
                + "] to nETBIOSName " + nETBIOSName);
            newPrincipal = AuthnPrincipal.make(principal.getName(), namespace, nETBIOSName);
            builder.add(newPrincipal);
          }
        } catch (NamingException e) {
          // we want to swallow this exception - we are probably in the wrong forest, so noop 
        }
        expirationTime = view.getConfiguredExpirationTime();
        return AuthnSessionState.of(
            view.getAuthority(), Verification.verified(expirationTime, builder.build()));
      }
    } else {
      expirationTime = view.getCredentialExpirationTime(principal);
    }
    ImmutableSet.Builder<Group> groupsBuilder = ImmutableSet.builder();
    if (mech.isEnableGroupLookup()) {
      if (!view.hasVerifiedPrincipal() && !mech.isEnableAuthn()) {
        gsaLogger.info(view.getRequestId(), "LDAP Auth failed; cannot lookup"
            + " groups without a verified user identity.");
        throw new AuthnModuleException("No verified principal while looking up groups.");
      }
      gsaLogger.info(view.getRequestId(), "LDAP Auth: Looking up groups for user "
          + idToLog);
      lookupGroups(ldapClient, principal.getName(), groupsBuilder, view);
    }
    if (mech.isEnableImplicitEveryone()) {
      groupsBuilder.add(Group.make(IMPLICIT_EVERYONE, view.getCredentialGroup().getName()));
    }
    Set<Group> groups = groupsBuilder.build();
    if (!groups.isEmpty()) {
      builder.add(view.extendGroupMemberships(groups));
    }
    return AuthnSessionState.of(view.getAuthority(),
        Verification.verified(expirationTime, builder.build()));
  }

  private static void lookupGroups(LDAPClient ldapClient, String username,
      ImmutableSet.Builder<Group> groupsBuilder, SessionView view) {
    String namespace = view.getCredentialGroup().getName();
    try {
      String dn = ldapClient.getUserDN(username);
      Set<NameAndDomain> ldapGroups = ldapClient.getGroupsWithUser(username, dn);
      for (NameAndDomain ldapGroup : ldapGroups) {
        switch (ldapClient.groupResolutionFormat()) {
          case CN:
          case SAM_ACCOUNT_NAME:
            groupsBuilder.add(Group.make(ldapGroup.getName(), namespace, 
                ldapClient.getDomain(ldapGroup.getDomain())));
            break;
          case DN:
            groupsBuilder.add(Group.make(ldapGroup.getName(), namespace));
            break;
          default:
            logger.warning(
                "Wrong Group resolution format : " + ldapClient.groupResolutionFormat());
            break;
        }
      }
      gsaLogger.info(view.getRequestId(), "LDAP Auth: " + ldapGroups.size()
          + " groups found.");
    } catch (NamingException e) {
      logger.log(
          Level.WARNING, view.logMessage("Error getting groups for %s: ", username), e);
      return;
    }
  }

  @VisibleForTesting
  LDAPClient getLDAPClient(AuthnMechLdap mech) {
    synchronized (this) {
      if (ldapClientForTesting != null) {
        return ldapClientForTesting;
      }
    }
    LDAPClient ldapClient = new LDAPClient();
    ldapClient.setHostPort(mech.getHostport());
    ldapClient.setAnonBindIdentity(mech.getBindDn(), mech.getPassword());
    ldapClient.setBase(mech.getSearchBase());
    ldapClient.setUserSearchFilter(mech.getUserSearchFilter());
    ldapClient.setGroupSearchFilter(mech.getGroupSearchFilter());
    ldapClient.setGroupResolutionFormat(GroupResolutionFormat.fromString(
        mech.getGroupFormat()));
    if (ldapClient.groupResolutionFormat() == GroupResolutionFormat.INVALID) {
      ldapClient.setGroupResolutionFormat(GroupResolutionFormat.CN);
    }
    ldapClient.setSSLSupportType(SSLSupport.fromInt(mech.getSslSupport()));
    ldapClient.setSupportedAuthMethods(AuthMethod.fromInt(mech.getSupportedAuthMethods()));
    ldapClient.setTimeout(mech.getTimeout());
    return ldapClient;
  }
}
