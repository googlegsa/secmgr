// Copyright 2013 Google Inc.
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

package com.google.enterprise.secmgr.authncontroller;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Sets;
import com.google.enterprise.policychecker.AclUtil;
import com.google.enterprise.secmgr.authncontroller.ExportedState.Credentials;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.enterprise.supergsa.security.AclPrincipals;
import com.google.inject.Singleton;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;

/**
 * This class manages the trust set up of the system. It checks if a session is from a trusted user.
 */
@Singleton
@ThreadSafe
public final class TrustManager {
  private static final Logger logger = Logger.getLogger(TrustManager.class.getName());

  @GuardedBy("this") private Set<AclPrincipal> principals;

  @GuardedBy("this") private String confFilename = null;

  // The modification time of the configuration file when last read.
  @GuardedBy("this") private long confTime;

  private final AclPrincipalStore aclPrincipalStore = AclPrincipalStoreFactory.create();

  @Inject
  private TrustManager() {
    reset();
    confTime = 0;
  }

  @VisibleForTesting
  synchronized void setConfFile(String filename) {
    confFilename = filename;
  }

  private synchronized boolean changedConfig()
      throws FileNotFoundException {
    File file = FileUtil.getContextFile(confFilename);
    long time = file.lastModified();

    if (time == 0) {
      logger.warning("No file " + file);
      throw new FileNotFoundException("No such file: " + file);
    }

    if (time == confTime) {
      return false;
    }

    confTime = time;
    return true;
  }

  /**
   * Reads from conf file and populates the internal map.
   */
  private void loadIfChanged() throws IOException {
    if (confFilename == null) {
      confFilename = ConfigSingleton.getTrustFilename();
    }
    try {
      while (changedConfig()) {
        load();
      }
    } catch (FileNotFoundException e) {
      logger.warning("Could not find trust conf file: " + confFilename);
    }
  }

  @VisibleForTesting
  synchronized void load() throws IOException {
    reset();
    File file = FileUtil.getContextFile(confFilename);
    principals.addAll(aclPrincipalStore.load(file.toString()));
  }

  @VisibleForTesting
  synchronized void reset() {
    principals = Sets.newHashSet();
  }

  /**
   * Using recordio, writes each principal as a log entry.
   */
  public synchronized void writeToFile(final AclPrincipals principals, String filename)
      throws IOException {
    aclPrincipalStore.store(principals, MoreObjects.firstNonNull(filename, confFilename));
  }

  /**
   * Checks whether a session is for a trusted user.
   * @param state The session state
   * @return Whether it's for a trusted user.
   */
  public boolean isTrusted(ExportedState state) {
    try {
      loadIfChanged();
    } catch (IOException e) {
      logger.log(Level.SEVERE, "Failed to load trust file.", e);
      e.printStackTrace();
    }

    ImmutableList<Credentials> credentials = state.getAllVerifiedCredentials();
    for (Credentials credential : credentials) {
      // The trust users are normally setup once and rarely change.
      // Otherwise consider use ReadWriteLock.
      AuthnPrincipal user = AuthnPrincipal.make(credential.getUsername(), credential.getNamespace(),
          credential.getDomain());
      logger.fine("user " + user.toString());
      AclPrincipal principal = AclUtil.authnPrincipalToAclPrincipal(user);
      if (principals.contains(principal)) {
        return true;
      }
      principal = AclUtil.authnPrincipalToAclPrincipalCaseInsensitive(user);
      if (principals.contains(principal)) {
        return true;
      }
      for (Group group : credential.getGroups()) {
        principal = AclUtil.groupToAclPrincipal(group);
        if (principals.contains(principal)) {
          return true;
        }
        principal = AclUtil.groupToAclPrincipalCaseInsensitive(group);
        if (principals.contains(principal)) {
          return true;
        }
      }
    }

    // No verified users or groups are trusted.
    return false;
  }

  // For testing
  private void printDebug() {
    for (AclPrincipal principal : principals) {
      logger.info("trusted " + principal.toString());
    }
  }
}
