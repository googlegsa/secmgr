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

import java.io.Serializable;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;

/**
 * This is an encapsulation of the data used by a credentials gatherer to
 * process a single identity.
 */
@ParametersAreNonnullByDefault
public interface CredentialsGathererElement  extends Serializable {

  /**
   * Gets the credentials gatherer this is an element for.
   *
   * @return The credentials gatherer.
   */
  @Nonnull
  public CredentialsGatherer getGatherer();

  /**
   * Gets the session view being used for gathering.
   *
   * @return The session view.
   */
  @Nonnull
  public SessionView getSessionView();

  /**
   * Gets a new element with a different view.
   *
   * @param view The new session view.
   * @return A new element.
   */
  @Nonnull
  public CredentialsGathererElement newSessionView(SessionView view);

  /**
   * Appends some session state to the element.
   *
   * @param sessionState The state to be stored.
   */
  public void addSessionState(AuthnSessionState sessionState);

  /**
   * Updates a session's state with this element's session state.
   *
   * @param session The session to be updated.
   */
  public void updateSessionState(AuthnSession session);

  /**
   * Sets the private state of this element to a given value.  This state is
   * reserved for the credentials gatherer and has no other purpose.
   *
   * @param state The new private state.
   */
  public void setPrivateState(@Nullable Object state);

  /**
   * Gets the private state of this element.
   *
   * @return The private state.
   */
  @Nullable
  public <T> T getPrivateState(Class<T> clazz);
}
