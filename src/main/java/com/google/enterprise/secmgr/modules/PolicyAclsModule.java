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
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.enterprise.policychecker.Acl;
import com.google.enterprise.policychecker.AclConfigurationStore;
import com.google.enterprise.policychecker.AclUtil;
import com.google.enterprise.policychecker.Authorizer;
import com.google.enterprise.policychecker.CompactUrlAclMap;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.IdentityUtil;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.inject.Singleton;
import com.google.inject.name.Named;

import org.joda.time.DateTimeUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;

/**
 * Adapter of com.google.enterprise.policychecker for security manager use.
 * Uses same data files authzchecker does.  Creates a Timer thread which
 * checks data-files' modified times and reloads on changes.
 */
@Singleton
@ThreadSafe
public final class PolicyAclsModule implements AuthzModule {
  private static final Logger logger = Logger.getLogger(PolicyAclsModule.class.getName());

  @GuardedBy("this") private Authorizer authorizer;
  private TimerTask reloader;

  @SuppressWarnings("unused")
  @Inject
  private PolicyAclsModule(
      @Named("PolicyConnector.dataReloadPeriodMillis") long dataReloadPeriodMillis) {
    this(null, dataReloadPeriodMillis);
  }

  @VisibleForTesting
  PolicyAclsModule(String aclUrlsFilename, long dataReloadPeriodMillis) {
    File aclUrls = null;
    try {
      // Acquire filename, which is constant throughout execution.
      aclUrls  = FileUtil.getContextFile(aclUrlsFilename != null
          ? aclUrlsFilename
          : ConfigSingleton.getAclUrlsFilename());
      logger.log(Level.FINE, "acl urls filename {0}", aclUrls);
    } catch (IOException e) {
      logger.log(Level.WARNING, "Do not know acl urls filename", e);
    }
    if (null != aclUrls) {  // Have file to watch for reloads.
      authorizer = readAuthorizer(aclUrls);
      logger.fine("Initial load completed");
      // TODO: Look into gracefully stopping Timer.
      // Potentially use a scheduled executor that's passed/injected in.
      // Or have AuthzModule interface have a shutdown.
      // Not a big deal cause: 
      //     1) we don't do graceful shutdown 
      //     2) Timer has finalize()
      reloader = new AclDataReloader(aclUrls);
      new Timer().schedule(reloader, dataReloadPeriodMillis, dataReloadPeriodMillis);
    }
  }

  @VisibleForTesting
  PolicyAclsModule(Authorizer authorizer) {
    Preconditions.checkNotNull(authorizer);
    this.authorizer = authorizer;
    this.reloader = null;
  }

  /** Access to authorizer is synchronized across thread boundries. */
  private synchronized Authorizer getAuthorizer() {
    return authorizer;
  }

  private synchronized void setAuthorizer(Authorizer authorizer) {
    this.authorizer = authorizer;
  }

  /**
   * Reads group and URL ACLs into an Authorizer.
   * @return An Authorizer or null when there are no URL ACLs.
   */
  private synchronized Authorizer readAuthorizer(File aclUrls) {
    AclConfigurationStore acs = new AclConfigurationStore(
        new CompactUrlAclMap(), aclUrls.getPath(), "");
    logger.info("Start loading");
    long beforeTimestamp = DateTimeUtils.currentTimeMillis();
    try {
      acs.reloadConfiguration();
    } catch (FileNotFoundException e) {
      logger.info("Could not load ACLs : " + e);
    }
    long time = DateTimeUtils.currentTimeMillis() - beforeTimestamp;
    logger.info("Finished loading in " + time + " milli seconds");
    return acs.getAclMap();
  }

  /** Composes File class with a modification timestamp. */
  private static class ChangingFile {
    final File file;
    long lastTimestamp;

    ChangingFile(File file) {
      this.file = file;
      lastTimestamp = file.lastModified();
    }

    /** Determines whether timestamp has changed since last invocation.
     *  Updates lastTimestamp to latest available modified time.
     *  @return Whether modified time has changed.
     */
    boolean hasBeenModified() {
      long currentTimestamp = file.lastModified();
      boolean modified;
      if (currentTimestamp == lastTimestamp) {
        modified = false;
      } else {
        lastTimestamp = currentTimestamp;
        modified = true;
        logger.info("Detected changed file: " + file);
      }
      return modified;
    }
  }

  /** Reloads and reassigns authorizer on ACL data file changes. */
  private class AclDataReloader extends TimerTask {
    final ChangingFile aclUrls;

    AclDataReloader(File aclUrls) {
      this.aclUrls = new ChangingFile(aclUrls);
    }

    @Override
    public final synchronized void run() {
      try {
        boolean haveNewUrls = aclUrls.hasBeenModified();
        if (haveNewUrls) {
          Authorizer candidate = readAuthorizer(aclUrls.file);
          if (candidate == null) {
            logger.warning("Skipping assigning null authorizer.");
          } else {
            setAuthorizer(candidate);
            logger.info("PolicyAclsModule reloaded");
          }
        }
      } catch (RuntimeException e) {
        // Preventative measure:
        // A RuntimeException in TimerTask causes Timer to be killed and no
        // further reloads are scheduled. Here we stop the killing exception.
        logger.log(Level.WARNING, "reload exception", e);
      }
    }
  }

  public void reload() {
    if (reloader == null) {
      return;
    }
    reloader.run();
  }

  /**
   * @param resources Strings representing URLs to be evaluated.
   * @param view A session view to get credentials from.
   * @return A map containing an {@link AuthzStatus} for each given URL.
   */
  @Override
  public AuthzResult authorize(Collection<Resource> resources, SessionView view, FlexAuthzRule rule)
      throws IOException {
    // TODO: change this authorizer, its caller, the ACL engine, and the
    // admin console so that all usernames and groups are simultaneously passed
    // to the ACL engine for authorization.
    Collection<String> urls = Resource.resourcesToUrls(resources);
    AuthnPrincipal principal = view.getVerifiedPrincipal();
    if (principal == null) {
      logger.info(view.logMessage("No verified principal"));
      return AuthzResult.makeIndeterminate(urls);
    }
    AuthnPrincipal dumbedDownPrincipal;
    if (principal.getDomain() != null) {
      dumbedDownPrincipal = AuthnPrincipal.make(principal.getName(),
          principal.getNamespace(),
          IdentityUtil.normalizeDomain(principal.getDomain()));
    } else {
      dumbedDownPrincipal = principal;
    }
    boolean lateBinding = false;
    lateBinding = ConfigSingleton.getLateBindingAcl();
    ImmutableSet<Group> groups = view.getGroups();
    ImmutableSet.Builder<AclPrincipal> aclPrincipalsBuilder = ImmutableSet.builder();
    Group dumbedDownGroup;
    for (Group group : groups) {
      dumbedDownGroup = Group.make(group.getName(), group.getNamespace(),
          IdentityUtil.normalizeDomain(group.getDomain()));
      aclPrincipalsBuilder.add(AclUtil.groupToAclPrincipal(dumbedDownGroup));
      aclPrincipalsBuilder.add(AclUtil.groupToAclPrincipalCaseInsensitive(dumbedDownGroup));
    }
    aclPrincipalsBuilder.add(AclUtil.authnPrincipalToAclPrincipal(dumbedDownPrincipal));
    aclPrincipalsBuilder.add(
        AclUtil.authnPrincipalToAclPrincipalCaseInsensitive(dumbedDownPrincipal));
    ImmutableSet<AclPrincipal> aclPrincipals = aclPrincipalsBuilder.build();
    AuthzResult.Builder builder = AuthzResult.builder(urls);
    for (String url : urls) {
      builder.put(url, authorize(url, view, aclPrincipals.asList(), lateBinding));
    }
    return builder.build();
  }

  private AuthzStatus authorize(String url, SessionView view, List<AclPrincipal> aclPrincipals,
      boolean lateBinding) throws IOException {
    // Call getAuthorizer() to make sure Thread sees current value.
    Authorizer localAuthorizer = getAuthorizer();
    if (localAuthorizer == null) {
      return AuthzStatus.INDETERMINATE;
    }
    Acl acl = localAuthorizer.get(url);
    if (acl != null) {
      AuthzStatus status = AclUtil.authorize(acl, aclPrincipals);
      return (lateBinding && AuthzStatus.PERMIT == status) ? AuthzStatus.INDETERMINATE : status;
    }
    if (acl != null) {
      logger.warning(view.logMessage("Unknown Acl type: %s", acl.getClass()));
    }
    return AuthzStatus.INDETERMINATE;
  }
}
