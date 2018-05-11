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
 * An abstract type for matcher stores.  A store takes a value and a state,
 * stores the value in the state, and returns the new state.
 *
 */
@ParametersAreNonnullByDefault
public interface Store {
  /**
   * Stores a given value in a given state, returning the new state.
   *
   * @param value The value to be stored.
   * @param state The state to store it in.
   * @return The new state.
   */
  @Nonnull
  public State put(Object value, State state);
}
