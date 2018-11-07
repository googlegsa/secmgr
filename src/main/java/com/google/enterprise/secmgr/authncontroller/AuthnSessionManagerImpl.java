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
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.sessionmanager.RedisRepository;
import com.google.inject.Singleton;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Formatter;
import java.util.Random;
import javax.servlet.http.HttpServletRequest;
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

  @GuardedBy("this") private long sessionIdleMillis;

  private static final Random random = new SecureRandom();

  @Inject
  private RedisRepository redisRepository;

  @Inject
  @VisibleForTesting
  AuthnSessionManagerImpl() {
    sessionIdleMillis = SecurityManagerUtil.getGsaSessionIdleMillis();
  }

  /* New Session Functions*/

  @Override
  public AuthnSession findSessionById(String sessionId) {
    return redisRepository.loadSession(sessionId);
  }

  @Override
  public AuthnSession findSession(HttpServletRequest request) {
    String sessionId = SessionUtil.findGsaSessionId(request);
    AuthnSession session = (AuthnSession) request.getAttribute(AuthnSession.AUTHN_SESSION);
    if (session != null) {
      return session;
    } else {
      session = findSessionById(sessionId);
      request.setAttribute(AuthnSession.AUTHN_SESSION, session);
      return session;
    }
  }

  @Override
  public AuthnSession createPersistentSession(HttpServletRequest request) throws IOException {
    AuthnSession session = createSession();
    request.setAttribute(AuthnSession.AUTHN_SESSION, session);
    return session;
  }

  @Override
  public AuthnSession createSession() throws IOException {
    AuthnSession session = new AuthnSession(ConfigSingleton.getConfig(), genSessionId());
    return session;
  }

  @Override
  public void saveSession(AuthnSession authnSession) {
    redisRepository.storeSession(authnSession);
  }

  @Override
  public void updateSessionTTL(AuthnSession authnSession) {
    redisRepository.updateSessionTTL(authnSession);
  }

  private String genSessionId() {
    byte[] randomBytes = new byte[16];
    random.nextBytes(randomBytes);
    StringBuilder sidBuilder =
        new StringBuilder(randomBytes.length * 2);
    random.nextBytes(randomBytes);
    sidBuilder.setLength(0);
    Formatter f = new Formatter(sidBuilder);
    for (byte b : randomBytes) {
      f.format("%02x", b);
    }
    return f.toString();
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
  public synchronized void reset() {
    sessionIdleMillis = SecurityManagerUtil.getGsaSessionIdleMillis();
  }
}
