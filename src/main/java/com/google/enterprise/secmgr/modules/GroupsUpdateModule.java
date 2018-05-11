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
package com.google.enterprise.secmgr.modules;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.logmanager.LogClientParameters;
import com.google.enterprise.policychecker.AclConfigurationStore;
import com.google.enterprise.policychecker.AclUtil;
import com.google.enterprise.policychecker.CompactUrlAclMap;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnModule;
import com.google.enterprise.secmgr.authncontroller.AuthnModuleException;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.MemberToGroupsResolverMapProvider;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.config.AuthnMechGroups;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.inject.Singleton;
import java.io.File;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;
import org.joda.time.DateTimeUtils;

/**
 * Authentication module for updating groups information at authentication time.
 */
@Singleton
@ThreadSafe
public final class GroupsUpdateModule implements AuthnModule {
  private static final long FILE_RELOAD_INTERVAL_MILLIS = 300000;  // 5 mins

  private static final LogClient gsaLogger =
      new LogClient("Security Manager", SecurityManagerUtil.getLogManagerServer());
  private static final Logger logger = Logger.getLogger(GroupsUpdateModule.class.getName());

  private final ScheduledExecutorService executorService;
  private final List<String> groupSources;  // filenames with group definitions
  private final List<MemberToGroupsResolverMapProvider> groupDefs;  // current group defs

  private static long getGsaGroupsFileReloadTime() {
    String groupsFileReloadTimeStr = System.getProperty("gsa.groupsfilereloadtime");
    if (Strings.isNullOrEmpty(groupsFileReloadTimeStr)) {
      return FILE_RELOAD_INTERVAL_MILLIS;
    }
    return Long.parseLong(groupsFileReloadTimeStr);
  }

  @Inject
  GroupsUpdateModule() throws IOException {
    this(getGsaGroupsFileReloadTime(), new String[] {
        ConfigSingleton.getGdataGroupsFilename(), ConfigSingleton.getFedGroupsFilename()},
        Optional.<ScheduledExecutorService>absent());
  }

  @VisibleForTesting
  GroupsUpdateModule(long fileReloadIntervalMillis, String groupdefsFilenames[],
      Optional<ScheduledExecutorService> testExecutorService) {
    List<String> tmpGroupSources = new ArrayList<>();
    List<MemberToGroupsResolverMapProvider> tmpProviders = new ArrayList<>();
    for (String groupdefFilename : groupdefsFilenames) {
      Preconditions.checkNotNull(groupdefsFilenames);
      tmpProviders.add(new MemberToGroupsResolverMapProvider());
      tmpGroupSources.add(groupdefFilename);
    }
    // Make instance variable immutable.
    groupSources = Collections.unmodifiableList(tmpGroupSources);
    groupDefs = Collections.unmodifiableList(tmpProviders);
    
    // Initialize scheduler
    executorService = testExecutorService.isPresent() 
        ? testExecutorService.get() : Executors.newScheduledThreadPool(groupSources.size());
    
    // Schedule reloading each group defintion sources.
    for (int i = 0; i < groupSources.size(); i++) {
      scheduleReadGroupsFromFile(i, fileReloadIntervalMillis);
    }
  }

  @VisibleForTesting
  MemberToGroupsResolverMapProvider getMemberGroupsProvider(int source) {
    return groupDefs.get(source);
  }

  /**
   * Overrides available group definitions with those in provided files. Stops all reload tasks,
   * so this data will be available until a future force.
   */
  @VisibleForTesting
  public void forceOverrideMembershipDataForTest(
      String gdataInputFilename, String feedInputFilename) {
    executorService.shutdown();
    readInto(groupDefs.get(0), gdataInputFilename);
    readInto(groupDefs.get(1), feedInputFilename);
  }

  private static void readInto(MemberToGroupsResolverMapProvider def, String dataFilename) {
    AclConfigurationStore store =
        new AclConfigurationStore(new CompactUrlAclMap(), "", dataFilename);
    long beforeGenerateMapTimestamp = DateTimeUtils.currentTimeMillis();
    long timeToGenerateMap;
    def.regenerateMemberToGroupsMap(store);
    timeToGenerateMap = DateTimeUtils.currentTimeMillis() - beforeGenerateMapTimestamp;
    logger.log(Level.INFO, MessageFormat.format(
        "User to groups map from {0} was generated using {1} milli seconds",
        dataFilename, timeToGenerateMap));
  }

  private void scheduleReadGroupsFromFile(int sourceIndex, long fileReloadIntervalMillis) {
    String filename = groupSources.get(sourceIndex);
    File aclGroups = FileUtil.getContextFile(filename);
    @SuppressWarnings("unused") // go/futurereturn-lsc
    Future<?> possiblyIgnoredError =
        executorService.scheduleWithFixedDelay(
            new GroupDataReloader(aclGroups, sourceIndex),
            0,
            fileReloadIntervalMillis,
            TimeUnit.MILLISECONDS);
  }

  @Override
  protected void finalize() {
    executorService.shutdown();
  }

  /** File with a modification timestamp. */
  private static class ChangingFile {
    final File file;
    Optional<Long> lastTimestamp;

    ChangingFile(File file) {
      this.file = file;
      lastTimestamp = Optional.absent();
    }

    /**
     * Returns true when timestamp has changed since last invocation or called first time.
     * Updates lastTimestamp to latest available modified time.
     */
    boolean hasBeenModifiedOrFirstAccess() {
      long currentTimestamp = file.lastModified();
      boolean modified = !lastTimestamp.isPresent() || currentTimestamp != lastTimestamp.get();
      lastTimestamp = Optional.of(currentTimestamp);
      return modified;
    }
  }

  /** Timer task which reloads and reassigns groups on group file changes. */
  private class GroupDataReloader implements Runnable {
    final ChangingFile aclFile;
    final int sourceIndex;

    GroupDataReloader(File file, int sourceIndex) {
      this.aclFile = new ChangingFile(file);
      this.sourceIndex = sourceIndex;
    }

    @Override
    public final void run() {
      try {
        if (aclFile.file.exists() && aclFile.hasBeenModifiedOrFirstAccess()) {
          readInto(groupDefs.get(sourceIndex), aclFile.file.getPath());
        }
      } catch (RuntimeException re) {
        // Preventative measure: A RuntimeException causes the executor service to stop running
        // scheduled tasks. Therefore we swallow this exception here (in order to keep us running).
        logger.log(Level.WARNING, "error during reload", re);
      }
    }
  }

  @Override
  public boolean willHandle(SessionView view) {
    return view.getMechanism() instanceof AuthnMechGroups;
  }

  @Override
  public AuthnSessionState authenticate(SessionView view) throws AuthnModuleException {
    AuthnPrincipal principal = view.getPrincipal();
    AuthnController.check(principal != null, "Missing principal");
    if (!view.hasVerifiedPrincipal()) {
      gsaLogger.info(
          view.getRequestId(),
          "Groups Auth failed; cannot lookup groups without a verified user identity.");
      throw new AuthnModuleException("No verified principal while looking up groups.");
    }

    String idToLog = LogClientParameters.recordUsernames
        ? principal.getName() : LogClientParameters.ID_NOT_LOGGED;
    gsaLogger.info(
        view.getRequestId(),
        "GroupsUpdateModule Auth: Looking up groups for user: " + idToLog);
    long expirationTime = view.getCredentialExpirationTime(principal);
    ImmutableSet.Builder<AclPrincipal> membersBuilder = ImmutableSet.builder();
    AclPrincipal user = AclUtil.authnPrincipalToAclPrincipal(principal);
    membersBuilder.add(user);
    for (Group userGroup : view.getGroups()) {
      AclPrincipal groupPrincipal = AclUtil.groupToAclPrincipal(userGroup);
      membersBuilder.add(groupPrincipal);
    }

    ImmutableSet.Builder<Group> groupsBuilder = ImmutableSet.builder();
    lookupGroups(membersBuilder.build(), groupsBuilder);
    Set<Group> groups = groupsBuilder.build();

    ImmutableSet.Builder<Credential> builder = ImmutableSet.builder();
    if (!groups.isEmpty()) {
      builder.add(view.extendGroupMemberships(groups));
      gsaLogger.info(
          view.getRequestId(),
          "GroupsUpdateModule Authn: " + groups.size() + " groups found.");
    } else {
      idToLog = LogClientParameters.recordUsernames
          ? user.toString() : LogClientParameters.ID_NOT_LOGGED;
      gsaLogger.info(
          view.getRequestId(),
          "GroupsUpdateModule did not find groups for: " + idToLog);
    }
    return AuthnSessionState.of(
        view.getAuthority(), Verification.verified(expirationTime, builder.build()));
  }

  /**
   * Looks up groups for a set of members and adds the groups to an ImmutableSet Builder object.
   *
   * @param members a set of members to be looked up for the groups they belong to
   * @param groupsBuilder an ImmutableSet Builder object which has all the groups for the members
   */
  public void lookupGroups(ImmutableSet<AclPrincipal> members,
      ImmutableSet.Builder<Group> groupsBuilder) {
    for (int i = 0; i < groupDefs.size(); i++) {
      if (groupDefs.get(i).getResolver() == null) {
        continue;
      }

      long beforeMapLookupTimestamp = DateTimeUtils.currentTimeMillis();
      for (AclPrincipal member : members) {
        Set<AclPrincipal> groups =
            groupDefs.get(i).getResolver().getAllGroupsForUser(member);
        if (groups != null) {
          for (AclPrincipal memberGroup : groups) {
            groupsBuilder.add(
                Group.make(memberGroup.getName(),
                memberGroup.hasNameSpace() ? memberGroup.getNameSpace() : null,
                memberGroup.hasDomain() ? memberGroup.getDomain().getName() : null));
          }
        }
      }
      long timeToLookupMap = DateTimeUtils.currentTimeMillis() - beforeMapLookupTimestamp;
      logger.log(Level.INFO, MessageFormat.format(
          "Lookup groups from source {0} took {1} milli seconds",
          groupSources.get(i), timeToLookupMap));
    }
  }
}
