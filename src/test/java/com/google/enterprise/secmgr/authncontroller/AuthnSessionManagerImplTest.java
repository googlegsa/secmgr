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

import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.joda.time.DateTimeUtils;

/**
 * Unit tests for {@link AuthnSessionManagerImpl}.
 */
public final class AuthnSessionManagerImplTest extends SecurityManagerTestCase {

  private static final long ONE_SEC = 1 * 1000;
  private static final long THREE_SEC = 1 * ONE_SEC;
  private static final long FIVE_SEC = 5 * ONE_SEC;

  private static final long[] OFFSETS = new long[] { -FIVE_SEC, -THREE_SEC, -ONE_SEC, ONE_SEC,
      THREE_SEC, FIVE_SEC + ONE_SEC};

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
    AuthnSession session = AuthnSession.newInstance();
    manager.saveSession(session);
    String sessionId = session.getSessionId();
    tryGetSession(true, sessionId, session);
  }

  private void tryGetSession(boolean isValid, String sessionId, AuthnSession session) {
    if (isValid) {
      AuthnSession result = manager.findSessionById(sessionId);
      assertNotNull(result);
      assertEquals(sessionId, result.getSessionId());
      assertTrue(EqualsBuilder.reflectionEquals(session, result, true));
    } else {
      assertNull(manager.findSessionById(sessionId));
    }
  }

  public void testGetIdleMillisFromFlag() {
    System.setProperty("gsa.sessionidletime", "864000");
    AuthnSessionManagerImpl testManager = new AuthnSessionManagerImpl();
    assertEquals(864000000, testManager.getSessionIdleMillis());
  }

  public void testBasicExpirationChangeIdle()
      throws IOException {
    for (long offset : OFFSETS) {
      reset();
      manager.setSessionIdleMillis(FIVE_SEC);
      tryBasicExpiration(offset, FIVE_SEC);
    }
  }

  private void tryBasicExpiration(long offset, long sessionIdleTime)
      throws IOException {
    AuthnSession session = AuthnSession.newInstance();
    String sessionId = session.getSessionId();
    manager.saveSession(session);
    try {
      long sleepTime = sessionIdleTime + offset;
      Thread.sleep (sleepTime);
    } catch (InterruptedException e) {
      throw new RuntimeException(e);
    }
    tryGetSession(offset <= 0, sessionId, session);
  }
}
