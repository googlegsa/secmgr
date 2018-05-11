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

package com.google.enterprise.secmgr.authncontroller;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.inject.Singleton;

import org.joda.time.DateTimeUtils;

import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;

/**
 * An implementation of an authentication session manager.
 */
@ThreadSafe
@Singleton
public final class AuthnSessionManagerImpl implements AuthnSessionManager {
  private static final Logger logger = Logger.getLogger(AuthnSessionManagerImpl.class.getName());

  // User to session id map.
  @GuardedBy("this") private final Map<AuthnPrincipal, String> userSessionMap;
  @GuardedBy("this") private final Map<String, AuthnSession> sessionMap;
  @GuardedBy("this") private final Map<AuthnSession, Long> refTimeMap;
  @GuardedBy("this") private long sessionIdleMillis;

  @Inject
  @VisibleForTesting
  AuthnSessionManagerImpl() {
    sessionMap = Maps.newHashMap();
    userSessionMap = Maps.newHashMap();
    refTimeMap = Maps.newHashMap();
    sessionIdleMillis = SecurityManagerUtil.getGsaSessionIdleMillis();
  }

  @Override
  public synchronized void registerSession(AuthnSession session) {
    long now = DateTimeUtils.currentTimeMillis();
    deleteExpiredSessions(now);
    sessionMap.put(session.getSessionId(), session);
    refTimeMap.put(session, now);
    logger.info("Register session " + session.getSessionId());
  }

  @Override
  public synchronized AuthnSession getSession(String sessionId) {
    long now = DateTimeUtils.currentTimeMillis();
    deleteExpiredSessions(now);
    AuthnSession session = sessionMap.get(sessionId);
    if (session != null) {
      refTimeMap.put(session, now);
    }
    return session;
  }

  @Override
  public synchronized void addUserSession(AuthnPrincipal user, String sessionId) {
    userSessionMap.put(user, sessionId);
  }

  @Override
  public synchronized AuthnSession getUserSession(AuthnPrincipal user) {
    String sessionId = userSessionMap.get(user);
    if (sessionId != null) {
      return getSession(sessionId);
    }
    return null;
  }

  @Override
  public synchronized void setSessionIdleMillis(long sessionIdleMillis) {
    this.sessionIdleMillis = sessionIdleMillis;
  }

  @GuardedBy("this")
  private void deleteExpiredSessions(long now) {
    long minRefTime = (now - sessionIdleMillis);
    List<AuthnSession> toDelete = Lists.newArrayList();
    for (Map.Entry<AuthnSession, Long> entry : refTimeMap.entrySet()) {
      if (entry.getValue() < minRefTime) {
        toDelete.add(entry.getKey());
      }
    }
    for (AuthnSession session : toDelete) {
      logger.fine("Deleting expired session " + session.getSessionId());
      sessionMap.remove(session.getSessionId());
      refTimeMap.remove(session);
      AuthnPrincipal user = getUser(session);
      if (user != null) {
        userSessionMap.remove(user);
      }
    }
  }

  @VisibleForTesting
  long getSessionIdleMillis() {
    return sessionIdleMillis;
  }

  @VisibleForTesting
  AuthnPrincipal getUser(AuthnSession session) {
    SessionView view = session.getSnapshot().getPrimaryVerifiedView();
    if (view != null) {
      return view.getPrincipal();
    }
    return null;
  }

  @VisibleForTesting
  Long getSessionRef(AuthnSession session) {
    return refTimeMap.get(session);
  }

  @VisibleForTesting
  public synchronized void reset() {
    sessionMap.clear();
    refTimeMap.clear();
    sessionIdleMillis = SecurityManagerUtil.getGsaSessionIdleMillis();
  }
}
