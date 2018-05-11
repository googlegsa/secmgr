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

/**
 * The authentication-session manager.  Tracks sessions and when they were last
 * used.  May eventually support garbage collection and session expiration.
 */
public interface AuthnSessionManager {
  /**
   * Register an authentication session.
   *
   * @param session The session to register.
   */
  public void registerSession(AuthnSession session);

  /**
   * Get a previously-registered session.
   *
   * @param sessionId The ID of the saved session.
   * @return The saved session, or null if there's none.
   */
  public AuthnSession getSession(String sessionId);

  /**
   * Associates a user to a session id.
   * @param user The user
   * @param sessionId The ID of the session.
   */
  public void addUserSession(AuthnPrincipal user, String sessionId);

  /**
   * Gets the session for the user.
   * @param user The user
   * @return The session for the user. Returns null if there is no existing session.
   */
  public AuthnSession getUserSession(AuthnPrincipal user);

  /**
   * Set the amount of time a session is allowed to be idle before it's expired.
   *
   * @param sessionIdleMillis The idle time in milliseconds.
   */
  public void setSessionIdleMillis(long sessionIdleMillis);
}
