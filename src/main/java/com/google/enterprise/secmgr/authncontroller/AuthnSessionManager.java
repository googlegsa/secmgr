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

import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

/**
 * The authentication-session manager.  Tracks sessions and when they were last
 * used.  May eventually support garbage collection and session expiration.
 */
public interface AuthnSessionManager {

  AuthnSession createPersistentSession(HttpServletRequest request) throws IOException;


  /**
   * Get a previously-registered session.
   *
   * @param sessionId The ID of the saved session.
   * @return The saved session, or null if there's none.
   */
  AuthnSession findSessionById(String sessionId);

  AuthnSession findSession(HttpServletRequest request);

  AuthnSession createSession() throws IOException;

  void saveSession(AuthnSession authnSession);

  void updateSessionTTL(AuthnSession authnSession);

  void setSessionIdleMillis(long sessionIdleMillis);
}
