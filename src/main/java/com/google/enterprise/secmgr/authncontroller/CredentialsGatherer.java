// Copyright 2009 Google Inc.
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

import java.io.Serializable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * An interface that all credentials gatherers must implement.  Used by the
 * authentication controller to manage the credentials-gathering process.
 */
@ParametersAreNonnullByDefault
public interface CredentialsGatherer extends Serializable {

  /**
   * Will this credentials gatherer handle a given session view?
   *
   * @param view The session view to be used for gathering.
   * @return True iff the gatherer will handle the authority.
   */
  public boolean willHandle(SessionView view);

  /**
   * Begins the process of gathering credentials.
   *
   * @param element The credentials-gatherer element being processed.
   * @param request The HTTP request from the user agent.
   * @param response The HTTP response to fill in to start the gathering process.
   * @return True if more responses need to be processed by this credential gatherer.
   */
  public boolean startGathering(CredentialsGathererElement element, HttpServletRequest request,
      HttpServletResponse response)
      throws IOException;

  /**
   * Continues the process of gathering credentials.
   *
   * @param element The credentials-gatherer element being processed.
   * @param request The HTTP request from the user agent.
   * @param response The HTTP response to fill in to start the gathering process.
   * @return True if more responses need to be processed by this credential gatherer.
   */
  public boolean continueGathering(CredentialsGathererElement element, HttpServletRequest request,
      HttpServletResponse response)
      throws IOException;
}
