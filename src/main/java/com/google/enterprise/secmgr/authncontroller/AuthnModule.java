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

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;

/**
 * An authentication module is responsible for verification of credentials, and
 * may additionally gather credentials if that can be done without communicating
 * with the user agent.
 */
@ParametersAreNonnullByDefault
public interface AuthnModule {
  /**
   * Will this module handle a given session view?
   *
   * @param view The session view to be used for gathering.
   * @return True iff the module will handle the view.
   */
  public boolean willHandle(SessionView view);

  /**
   * Runs an authentication module.
   *
   * @param view The session view with which the verification will be performed.
   * @return The incremental changes to the session state that the verification
   *     produced.
   * @throws AuthnModuleException if the authority can't finish the authentication.
   * @throws IOException if there are errors communicating with the authority.
   */
  @Nonnull
  public AuthnSessionState authenticate(SessionView view)
      throws IOException, AuthnModuleException;
}
