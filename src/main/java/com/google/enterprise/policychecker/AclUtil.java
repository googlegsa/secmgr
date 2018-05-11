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

package com.google.enterprise.policychecker;

import com.google.common.base.Strings;
import com.google.common.collect.Sets;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.supergsa.security.AclInheritance;
import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.enterprise.supergsa.security.Domain;
import com.google.enterprise.supergsa.security.GsaAcl;
import com.google.enterprise.supergsa.security.GsaAclEntry;
import com.google.enterprise.supergsa.security.GsaEntry;

import com.ibm.icu.text.Normalizer2;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.Nullable;

/**
 * Utililty functions for Acls.
 *
 */
public class AclUtil {

  private AclUtil() {}  // non-instantiable.

  /**
   * Unicode normalization functionality for standard Unicode normalization.
   */
  private static final Normalizer2 NORMALIZER =
      Normalizer2.getInstance(null, "nfkc_cf", Normalizer2.Mode.COMPOSE);

  private static final Logger logger = Logger.getLogger(AclUtil.class.getName());
  public static final String DEFAULT_NAMESPACE = "Default";

  public static AuthzStatus authorize(Acl acl, List<AclPrincipal> aclPrincipals) {
    if (acl == null  || aclPrincipals == null) {
      return AuthzStatus.INDETERMINATE;
    }
    // N.B.: DENY trumps PERMIT.
    return (allowsRead(acl, aclPrincipals) && !forbidsRead(acl, aclPrincipals))
        ? AuthzStatus.PERMIT
        : AuthzStatus.DENY;
  }

  private static boolean forbidsRead(Acl acl, List<AclPrincipal> principals) {
    return acl.forbidsReadToAnyAclPrincipal(principals);
  }

  private static boolean allowsRead(Acl acl, List<AclPrincipal> principals) {
    return acl.allowsReadToAnyAclPrincipal(principals);
  }

  public static AclPrincipal authnPrincipalToAclPrincipal(AuthnPrincipal authnPrincipal) {
    return buildAclPrincipal(AclPrincipal.SCOPE.USER, authnPrincipal.getName(),
        authnPrincipal.getNamespace(), authnPrincipal.getDomain(),
        AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE);
  }

  public static AclPrincipal authnPrincipalToAclPrincipalCaseInsensitive(
      AuthnPrincipal authnPrincipal) {
    return buildAclPrincipal(AclPrincipal.SCOPE.USER, authnPrincipal.getName(),
        authnPrincipal.getNamespace(), authnPrincipal.getDomain(),
        AclPrincipal.CaseSensitivity.EVERYTHING_CASE_INSENSITIVE);
  }


  public static AclPrincipal userNameToAclPrincipal(String username) {
    return buildAclPrincipal(AclPrincipal.SCOPE.USER, username, null, null,
        AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE);
  }

  public static AclPrincipal userNameToAclPrincipalCaseInsensitive(String username) {
    return buildAclPrincipal(AclPrincipal.SCOPE.USER, username, null, null,
        AclPrincipal.CaseSensitivity.EVERYTHING_CASE_INSENSITIVE);
  }

  public static AclPrincipal groupToAclPrincipal(String group) {
    return buildAclPrincipal(AclPrincipal.SCOPE.GROUP, group, null, null,
        AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE);
  }

  public static AclPrincipal groupToAclPrincipalCaseInsensitive(String group) {
    return buildAclPrincipal(AclPrincipal.SCOPE.GROUP, group, null, null,
        AclPrincipal.CaseSensitivity.EVERYTHING_CASE_INSENSITIVE);
  }

  public static AclPrincipal groupToAclPrincipal(Group group) {
    return buildAclPrincipal(AclPrincipal.SCOPE.GROUP, group.getName(), group.getNamespace(),
        group.getDomain(), AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE);
  }

  public static AclPrincipal groupToAclPrincipalCaseInsensitive(Group group) {
    return buildAclPrincipal(AclPrincipal.SCOPE.GROUP, group.getName(), group.getNamespace(),
        group.getDomain(), AclPrincipal.CaseSensitivity.EVERYTHING_CASE_INSENSITIVE);
  }

  /**
   * Adds a GsaEntry to the given ACL.
   *
   * @param acl the ACL to which the GsaEntry should be added
   * @param name the name of the principal to be added
   * @param scope the type of principal to be added (user or group)
   * @param access the access rights the principal should have
   * @return the GsaEntry which was added to the ACL
   */
  public static GsaEntry addGsaEntry(GsaAcl.Builder acl, String name, AclPrincipal.SCOPE scope,
      GsaEntry.ACCESS access) {
    AclPrincipal.Builder builder = AclPrincipal.newBuilder()
        .setName(name)
        .setScope(scope)
        .setNameSpace(DEFAULT_NAMESPACE)
        .setCaseSensitive(AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE);
    return addGsaEntry(acl, builder.build(), access);
  }

  /**
   * Adds a GsaEntry to the given ACL with PERMIT access.
   *
   * @param acl the ACL to which the GsaEntry should be added
   * @param name the name of the principal to be added
   * @param scope the type of principal to be added (user or group)
   * @return the GsaEntry which was added to the ACL
   */
  public static GsaEntry addGsaEntry(GsaAcl.Builder acl, String name, AclPrincipal.SCOPE scope) {
    return addGsaEntry(acl, name, scope, GsaEntry.ACCESS.PERMIT);
  }

  public static GsaEntry addGsaEntry(GsaAcl.Builder acl, AclPrincipal principal,
      GsaEntry.ACCESS access) {
    GsaAclEntry.Builder aclEntry = acl.addEntriesBuilder();
    GsaEntry.Builder entry = aclEntry.getGsaEntryBuilder();
    entry.setAccess(access);
    entry.setPrincipal(principal);
    GsaEntry ret = entry.build();
    aclEntry.build();
    return ret;
  }

  // Returns true if the name, domain, and namespace are all null or empty in the AclPrincipal.
  public static boolean isEmpty(AclPrincipal principal) {
    if (principal.hasDomain()) {
      return (Strings.isNullOrEmpty(principal.getName()) &&
          Strings.isNullOrEmpty(principal.getDomain().getName()) &&
          Strings.isNullOrEmpty(principal.getNameSpace()));
    } else {
      return (Strings.isNullOrEmpty(principal.getName()) &&
          Strings.isNullOrEmpty(principal.getNameSpace()));
    }
  }

  // Returns true if the name, namespace, and scope are all non-empty in the AclPrincipal.
  public static boolean isWellFormed(AclPrincipal principal) {
    return (!Strings.isNullOrEmpty(principal.getName()) &&
        (principal.getScope() == AclPrincipal.SCOPE.USER ||
         principal.getScope() == AclPrincipal.SCOPE.GROUP) &&
        !Strings.isNullOrEmpty(principal.getNameSpace()));
  }

  public static GsaEntry addGsaEntry(GsaAcl.Builder acl, AclPrincipal principal) {
    return addGsaEntry(acl, principal, GsaEntry.ACCESS.PERMIT);
  }

  /**
   * Utility class to maintain collections of permitted and denied user and group
   * ACLs.  Collections are sorted in canonical order.  The getters return
   * unmodifiable collections, so no defensive copies of the returned Collections
   * need be made.
   */
  public static class AclContent {

    /**
     * Holds inheritance data about parent of a given AclContent.
     *
     */
    public static class Inheritance {
      public Inheritance(String url, GsaAcl parent) {
        this.url = url;
        this.parent = AclContent.fromGsaAcl(parent);
      }
      public final String url;
      public final AclContent parent;
    }

    /**
     * Holds data about status of inheritance chain.
     */
    public static class ChainStatus {
      public ChainStatus(boolean isOk, String status) {
        this.isOk = isOk;
        this.status = status;
      }
      public final boolean isOk;
      public final String status;
    }

    private final Collection<String> permittedUsers, permittedGroups,
                                     deniedUsers, deniedGroups;
    private String inheritanceType;
    private Inheritance inheritance = null;
    private ChainStatus chainStatus = null;


    private AclContent() {
      permittedUsers = Sets.newTreeSet();
      permittedGroups = Sets.newTreeSet();
      deniedUsers = Sets.newTreeSet();
      deniedGroups = Sets.newTreeSet();
    }

    private Collection<String> getPrincipals(GsaEntry.ACCESS access, AclPrincipal.SCOPE scope) {
      switch(access) {
        case PERMIT:
          switch(scope) {
            case USER:
              return permittedUsers;
            case GROUP:
              return permittedGroups;
          }
          break;
        case DENY:
          switch(scope) {
            case USER:
              return deniedUsers;
            case GROUP:
              return deniedGroups;
          }
      }
      throw new IllegalArgumentException(
          String.format("Invalid ACCESS(%s) SCOPE(%s)", access.toString(), scope.toString()));
    }

    /**
     * Build representation of a principal in the format
     * ( namespace ) :: [ domain ] name (case-sensitivity)
     *
     * <p>If namespace is not present, it will be omitted, including () and ::.
     * If domain is not present, it will be omitted, including []
     *
     * <p>NOTE: if you change this format, update its explanation in
     * {@link ContentStatusHtml.gxp}
     */
    private static String principalAsString(AclPrincipal p) {
      StringBuilder result = new StringBuilder();
      if (!Strings.isNullOrEmpty(p.getNameSpace())) {
        result.append("( ");
        result.append(p.getNameSpace());
        result.append(" ) :: ");
      }
      if (p.hasDomain() && !Strings.isNullOrEmpty(p.getDomain().getName())) {
        result.append("[ ");
        result.append(p.getDomain().getName());
        result.append(" ] ");
      }
      result.append(p.getName());
      if (p.hasCaseSensitive()) {
        result.append(" (");
        switch (p.getCaseSensitive()) {
          case EVERYTHING_CASE_SENSITIVE:
            result.append("ECS"); break;
          case EVERYTHING_CASE_INSENSITIVE:
            result.append("ECI"); break;
          default: {
            logger.log(Level.WARNING, "Unkown case sensitivity: " + p.getCaseSensitive());
            result.append("UNKNOWN");
          }
        }
        result.append(")");
      }
      return result.toString();
    }


    public static AclContent fromGsaAcl(GsaAcl acl) {
      if (acl == null) {
        return null;
      }
      AclContent ac = new AclContent();
      for (GsaAclEntry gae : acl.getEntriesList()) {
        GsaEntry e = gae.getGsaEntry();
        ac.getPrincipals(e.getAccess(),
            e.getPrincipal().getScope()).add(principalAsString(e.getPrincipal()));
      }

      if (acl.hasMetadata() && acl.getMetadata().hasInheritance()) {
        AclInheritance aclInheritance = acl.getMetadata().getInheritance();
        // what kind of a parent are we?
        ac.inheritanceType = aclInheritance.getType().toString();
        // what kind of a parent do we have?
        ac.inheritance = new Inheritance(aclInheritance.getInheritFrom(),
            aclInheritance.hasParentAcl() ? aclInheritance.getParentAcl() : null);
        if (aclInheritance.hasStatus()) {
          boolean isOk = aclInheritance.getStatus() == AclInheritance.ChainStatus.CHAIN_OK;
          String status = null;
          switch (aclInheritance.getStatus()) {
            case CHAIN_OK:
              status = "CHAIN_OK"; break;
            case CHAIN_HAS_CYCLE:
              status = "CHAIN_HAS_CYCLE"; break;
            case INHERITANCE_DATA_MISSING:
              status = "INHERITANCE_DATA_MISSING"; break;
            case LOCAL_ID_LOOKUP_FAILURE:
              status = "LOCAL_ID_LOOKUP_FAILURE"; break;
            case INVALID_INHERITANCE_TYPE:
              status = "INVALID_INHERITANCE_TYPE"; break;
            default: {
              logger.log(Level.WARNING, "Unknown chain status: " + aclInheritance.getStatus());
              status = "ERROR";
            }
          }
          ac.chainStatus = new ChainStatus(isOk, status);
        }
      }

      if (Strings.isNullOrEmpty(ac.inheritanceType)) {
        ac.inheritanceType = AclInheritance.InheritanceType.LEAF_NODE.toString();
      }
      return ac;
    }

    public boolean hasPrincipals() {
      return !(permittedUsers.isEmpty() && permittedGroups.isEmpty() &&
          deniedUsers.isEmpty() && deniedGroups.isEmpty());
    }

    public boolean isEmpty() {
      return !hasPrincipals() && (inheritance == null) && (chainStatus == null);
    }

    /**
     * @return String representation of inheritance type of this Acl.
     * (Applies to all acls that inherit from this one.)  Meant for display in the UI.
     */
    public String getInheritanceType() {
      return inheritanceType;
    }

    public ChainStatus getChainStatus() {
      return this.chainStatus;
    }

    /**
     * @return data about this ACL's inheritance, or <code>null</code> if this
     * ACL does not inherit from other ACL's.
     *
     * It is an invariant that if this method returns <code>null</code>, then
     * getInheritanceType() returns "LEAF_NODE".
     */
    @Nullable public Inheritance getInheritance() {
      return inheritance;
    }

    /**
     * @return the permitted users
     */
    public Collection<String> getPermittedUsers() {
      return Collections.unmodifiableCollection(permittedUsers);
    }

    /**
     * @return the permitted groups
     */
    public Collection<String> getPermittedGroups() {
      return Collections.unmodifiableCollection(permittedGroups);
    }

    /**
     * @return the denied users
     */
    public Collection<String> getDeniedUsers() {
      return Collections.unmodifiableCollection(deniedUsers);
    }

    /**
     * @return the denied groups
     */
    public Collection<String> getDeniedGroups() {
      return Collections.unmodifiableCollection(deniedGroups);
    }
  }

  public static AclPrincipal buildAclPrincipal(AclPrincipal.SCOPE scope, String name,
      String namespace, String domain, AclPrincipal.CaseSensitivity caseSensitivity) {
    AclPrincipal.Builder builder = AclPrincipal.newBuilder();
    builder.setScope(scope);
    builder.setCaseSensitive(caseSensitivity);
    if (caseSensitivity == AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE) {
      builder.setName(name);
      setNamespaceinAclPrincipal(namespace, builder);
      setDomainInAclPrincipal(domain, builder);
    } else {
      builder.setName(NORMALIZER.normalize(name));
      if (namespace == null) {
        namespace = DEFAULT_NAMESPACE;
      }
      setNamespaceinAclPrincipal(NORMALIZER.normalize(namespace), builder);
      setDomainInAclPrincipal((domain == null) ? null : NORMALIZER.normalize(domain), builder);
    }
    return builder.build();
  }

  private static void setDomainInAclPrincipal(String domain, AclPrincipal.Builder builder) {
    if (!Strings.isNullOrEmpty(domain)) {
      builder.setDomain(Domain.newBuilder()
          .setName(domain)
          .setType(Domain.DomainType.NETBIOS)
          .build());
    }
  }

  private static void setNamespaceinAclPrincipal(String namespace, AclPrincipal.Builder builder) {
    if (!Strings.isNullOrEmpty(namespace)) {
      builder.setNameSpace(namespace);
    } else {
      builder.setNameSpace(DEFAULT_NAMESPACE);
    }
  }
}
