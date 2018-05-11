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

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;

/**
 * An abstract type for matcher operands.  A matcher operand is an object that
 * fetches a value from a given matcher state, returning both the value and a
 * new matcher state.
 * <p>
 * For example, an operand that pops a value off the stack will return the
 * popped value, and a new state containing a stack that's one value shorter.
 *
 */
@ParametersAreNonnullByDefault
public interface Operand {
  /**
   * Gets an operand value.
   *
   * @param state The current match state.
   * @return The operand result.
   */
  @Nonnull
  public OperandResult get(State state);
}
