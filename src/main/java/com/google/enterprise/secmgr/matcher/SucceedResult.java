// Copyright 2011 Google Inc.
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

package com.google.enterprise.secmgr.matcher;

import com.google.common.base.Preconditions;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * A result to be returned to the top-level matcher when the match has
 * succeeded.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
public final class SucceedResult implements Result {
  @Nonnull private final State state;
  @Nonnull private final Fail fail;

  private SucceedResult(State state, Fail fail) {
    Preconditions.checkNotNull(state);
    Preconditions.checkNotNull(fail);
    this.state = state;
    this.fail = fail;
  }

  /**
   * Gets a success result.
   *
   * @param state The state at which the match has succeeded.
   * @param fail The failure continuation to call to get more match results.
   * @return The corresponding result.
   */
  @Nonnull
  static Result make(State state, Fail fail) {
    return new SucceedResult(state, fail);
  }

  /**
   * Gets the state at which the match succeeded.
   */
  @Nonnull
  public State getState() {
    return state;
  }

  /**
   * Gets the failure continuation to call to get more match results.
   */
  @Nonnull
  public Fail getFail() {
    return fail;
  }
}
