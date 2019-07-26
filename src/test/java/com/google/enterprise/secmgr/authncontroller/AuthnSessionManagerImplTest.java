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

import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import org.joda.time.DateTimeUtils;

/**
 * Unit tests for {@link AuthnSessionManagerImpl}.
 */
public final class AuthnSessionManagerImplTest extends SecurityManagerTestCase {

  private static final int EPSILON = 100;

  private static final long ONE_MINUTE = 60 * 1000;

  private static final long[] OFFSETS = new long[] { -ONE_MINUTE, -10, -1, 1, 10, ONE_MINUTE };

  private final AuthnSessionManagerImpl manager;

  public AuthnSessionManagerImplTest() {
    manager
        = AuthnSessionManagerImpl.class.cast(
            ConfigSingleton.getInstance(AuthnSessionManager.class));
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    addTearDown(new TearDown() {
      @Override
      public void tearDown() throws Exception {
        reset();
      }
    });
  }

  private void reset() {
    manager.reset();
    DateTimeUtils.setCurrentMillisSystem();
  }

  public void testRegistration()
      throws IOException {
    // newInstance will add itself to the sessionmanager
    AuthnSession session = AuthnSession.newInstance();
    String sessionId = session.getSessionId();
    tryGetSession(true, sessionId, session);
  }

  private void tryGetSession(boolean isValid, String sessionId, AuthnSession session) {
    if (isValid) {
      AuthnSession result = manager.getSession(sessionId);
      assertNotNull(result);
      assertEquals(sessionId, result.getSessionId());
      assertEquals(session, result);
    } else {
      assertNull(manager.getSession(sessionId));
      assertNull(manager.getSessionRef(session));
    }
  }

  public void testGetIdleMillisFromFlag() {
    System.setProperty("gsa.sessionidletime", "864000");
    AuthnSessionManagerImpl testManager = new AuthnSessionManagerImpl();
    assertEquals(864000000, testManager.getSessionIdleMillis());
  }

  public void testBasicExpiration()
      throws IOException {
    for (long offset : OFFSETS) {
      reset();
      tryBasicExpiration(offset, SecurityManagerUtil.getGsaSessionIdleMillis());
    }
  }

  public void testBasicExpirationChangeIdle()
      throws IOException {
    for (long offset : OFFSETS) {
      reset();
      manager.setSessionIdleMillis(ONE_MINUTE);
      tryBasicExpiration(offset, ONE_MINUTE);
    }
  }

  private void tryBasicExpiration(long offset, long sessionIdleTime)
      throws IOException {
    AuthnSession session = AuthnSession.newInstance();
    String sessionId = session.getSessionId();
    manager.registerSession(session);
    DateTimeUtils.setCurrentMillisOffset(sessionIdleTime + offset);
    tryGetSession(offset <= 0, sessionId, session);
  }

  public void testCompoundExpiration()
      throws IOException {
    for (long offset : OFFSETS) {
      reset();
      tryCompoundExpiration(offset, SecurityManagerUtil.getGsaSessionIdleMillis());
    }
  }

  public void testCompoundExpirationChangeIdle()
      throws IOException {
    for (long offset : OFFSETS) {
      reset();
      manager.setSessionIdleMillis(ONE_MINUTE);
      tryCompoundExpiration(offset, ONE_MINUTE);
    }
  }

  private void tryCompoundExpiration(long offset, long sessionIdleTime)
      throws IOException {
    AuthnSession session = AuthnSession.newInstance();
    String sessionId = session.getSessionId();
    manager.registerSession(session);
    DateTimeUtils.setCurrentMillisOffset(sessionIdleTime - EPSILON);
    tryGetSession(true, sessionId, session);
    DateTimeUtils.setCurrentMillisOffset(sessionIdleTime - EPSILON + sessionIdleTime + offset);
    tryGetSession(offset <= 0, sessionId, session);
  }
}
