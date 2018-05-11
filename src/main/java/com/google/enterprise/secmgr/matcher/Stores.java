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
 * Implementations of standard stores.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
public final class Stores {
  private Stores() {
    throw new UnsupportedOperationException();
  }

  /**
   * Gets a store that replaces the stack.  The value being stored must be a
   * stack, otherwise the returned store will signal {@link ClassCastException}.
   */
  @Nonnull
  public static Store stack() {
    return STACK;
  }

  @Nonnull private static final Store STACK =
      new Store() {
        @Override
        public State put(Object value, State state) {
          return state.newStack(ValueStack.class.cast(value));
        }
      };

  /**
   * Gets a store that pushes a value onto the stack.
   */
  @Nonnull
  public static Store push() {
    return PUSH;
  }

  @Nonnull private static final Store PUSH =
      new Store() {
        @Override
        public State put(Object value, State state) {
          return state.newStack(state.getStack().push(value));
        }
      };

  /**
   * Gets a store that adds a value to a dictionary.
   *
   * @param key The key to use when adding the value.
   * @return The corresponding store.
   */
  @Nonnull
  public static Store put(final Object key) {
    Preconditions.checkNotNull(key);
    return new Store() {
      @Override
      public State put(Object value, State state) {
        return state.newDict(state.getDict().put(key, value));
      }
    };
  }
}
