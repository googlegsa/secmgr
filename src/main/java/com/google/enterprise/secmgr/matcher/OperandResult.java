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
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * The result type returned by operands.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
public final class OperandResult {
  @Nullable private final Object value;
  @Nonnull private final State state;

  private OperandResult(@Nullable Object value, State state) {
    this.value = value;
    this.state = state;
  }

  /**
   * Makes an operand result.
   *
   * @param value The operand's value.
   * @param state The state to continue with.
   * @return The corresponding operand result.
   */
  @Nonnull
  public static OperandResult make(@Nullable Object value, State state) {
    Preconditions.checkNotNull(state);
    return new OperandResult(value, state);
  }

  /**
   * Gets this result's operand value.
   */
  @Nullable
  public Object getValue() {
    return value;
  }

  /**
   * Gets this result's state.
   */
  @Nonnull
  public State getState() {
    return state;
  }
}
