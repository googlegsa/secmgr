/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.enterprise.secmgr.modules;

import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.identity.VerificationStatus;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;

/**
 * Common utilities used by modules.
 */
@ParametersAreNonnullByDefault
final class ModuleUtil {

  // Don't instantiate.
  private ModuleUtil() {
    throw new UnsupportedOperationException();
  }

  /**
   * Generates a standard authenticator result.
   *
   * @param view The session view used for the authentication.
   * @param status A verification status for the authentication.
   * @param verifiedCredentials Some credentials that were verified by the
   *     authentication.
   * @param cookies Some cookies that were received during the authentication.
   * @return An appropriate session-state result.
   */
  @Nonnull
  static AuthnSessionState standardAuthnResult(SessionView view, VerificationStatus status,
      Iterable<Credential> verifiedCredentials, Iterable<GCookie> cookies) {
    switch (status) {
      case VERIFIED:
        return
            AuthnSessionState.of(view.getAuthority(),
                Verification.verified(
                    view.getConfiguredExpirationTime(),
                    verifiedCredentials))
            .addCookies(view.getAuthority(), cookies);
      case REFUTED:
        return
            AuthnSessionState.of(view.getAuthority(), Verification.refuted(verifiedCredentials))
            .addCookies(view.getAuthority(), cookies);
      case INDETERMINATE:
        return indeterminateAuthnResult(view, cookies);
      default:
        throw new IllegalStateException("Unknown verification status: " + status);
    }
  }

  /**
   * Generates a standard authenticator result for an indeterminate status.
   *
   * @param view The session view used for the authentication.
   * @param cookies Some cookies that were received during the authentication.
   * @return An appropriate session-state result.
   */
  @Nonnull
  static AuthnSessionState indeterminateAuthnResult(SessionView view, Iterable<GCookie> cookies) {
    return AuthnSessionState.empty().addCookies(view.getAuthority(), cookies);
  }
}
