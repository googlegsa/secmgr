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

/**
 * A success continuation.  To be called by a matcher when the match has
 * succeeded.  The success continuation's behavior is provided by defining
 * {@link #applyInternal} in a subclass.
 *
 */
@ParametersAreNonnullByDefault
public abstract class Succeed {
  /**
   * Applies the continuation.  In order to properly support tail recursion,
   * this method returns a {@link TailCallResult} that the top-level matcher is
   * responsible for calling.
   *
   * @param state The state at which the match has succeeded.
   * @param fail The failure continuation to call if subsequent matching fails.
   * @return A {@link TailCallResult} that delegates to {@link #applyInternal}.
   */
  public Result apply(final State state, final Fail fail) {
    Preconditions.checkNotNull(state);
    Preconditions.checkNotNull(fail);
    return new TailCallResult() {
      @Override
      public Result call() {
        return applyInternal(state, fail);
      }
    };
  }

  /**
   * Implements the success continuation's behavior.  Called, indirectly, by
   * {@link #apply}.
   *
   * @param state The state at which the match has succeeded.
   * @param fail The failure continuation to call if subsequent matching fails.
   * @return A result of the actions taken by the success continuation.
   */
  @Nonnull
  protected abstract Result applyInternal(State state, Fail fail);
}
