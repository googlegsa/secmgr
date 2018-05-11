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

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * Implementations of standard operands.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
public final class Operands {
  private Operands() {
    throw new UnsupportedOperationException();
  }

  /**
   * Gets an operand that returns a given value, without modifying the matcher
   * state.
   *
   * @param value The value to be returned.
   * @return The corresponding operand.
   */
  @Nonnull
  public static Operand constant(final Object value) {
    Preconditions.checkNotNull(value);
    return new Operand() {
      @Override
      public OperandResult get(State state) {
        return OperandResult.make(value, state);
      }
    };
  }

  /**
   * Gets an operand that returns the position from a matcher state, without
   * modifying the matcher state.
   */
  @Nonnull
  public static Operand position() {
    return POSITION;
  }

  @Nonnull private static final Operand POSITION = new Operand() {
      @Override
      public OperandResult get(State state) {
        return OperandResult.make(state.getPosition(), state);
      }
    };

  /**
   * Gets an operand that returns the next character in the input sequence, and
   * moves the position forward one character.  If the position is at the end of
   * the input sequence, the operand returns {@code null} and doesn't modify the
   * state.
   */
  @Nonnull
  public static Operand nextChar() {
    return NEXT_CHAR;
  }

  @Nonnull private static final Operand NEXT_CHAR = new Operand() {
      @Override
      public OperandResult get(State state) {
        return state.getPosition().hasChar()
            ? OperandResult.make(
                state.getPosition().getChar(),
                state.newPosition(state.getPosition().nextPosition()))
            : OperandResult.make(null, state);
      }
    };

  /**
   * Gets an operand that returns the next several characters in the input
   * sequence, and moves the position forward that many characters.  If there
   * are not enough characters in the input sequence, the operand returns
   * {@code null} and doesn't modify the state.
   */
  @Nonnull
  public static Operand nextChars(@Nonnegative final int nChars) {
    Preconditions.checkArgument(nChars >= 0);
    return new Operand() {
      @Override
      public OperandResult get(State state) {
        return state.getPosition().hasChars(nChars)
            ? OperandResult.make(
                state.getPosition().getString(nChars),
                state.newPosition(state.getPosition().nextPosition(nChars)))
            : OperandResult.make(null, state);
      }
    };
  }

  /**
   * Gets an operand that returns the stack from a matcher state, without
   * modifying the matcher state.
   */
  @Nonnull
  public static Operand stack() {
    return STACK;
  }

  @Nonnull private static final Operand STACK = new Operand() {
      @Override
      public OperandResult get(State state) {
        return OperandResult.make(state.getStack(), state);
      }
    };

  /**
   * Gets an operand that returns the stack from a matcher state, and replaces
   * it with an empty stack.
   */
  @Nonnull
  public static Operand newStack() {
    return NEW_STACK;
  }

  @Nonnull private static final Operand NEW_STACK = new Operand() {
      @Override
      public OperandResult get(State state) {
        return OperandResult.make(
            state.getStack(),
            state.newStack(ValueStack.empty()));
      }
    };

  /**
   * Gets an operand that pops a value off the value stack.  If the stack is
   * empty, the operand returns {@code null} and doesn't modify the matcher
   * state.
   */
  @Nonnull
  public static Operand pop() {
    return POP;
  }

  @Nonnull private static final Operand POP = new Operand() {
      @Override
      public OperandResult get(State state) {
        return state.getStack().isEmpty()
            ? OperandResult.make(null, state)
            : OperandResult.make(
                state.getStack().top(),
                state.newStack(state.getStack().pop()));
      }
    };

  /**
   * Gets an operand that returns the top-most value on the matcher stack
   * without modifying the matcher state.  If the stack is empty, the operand
   * returns {@code null}.
   */
  @Nonnull
  public static Operand top() {
    return TOP;
  }

  @Nonnull private static final Operand TOP = new Operand() {
      @Override
      public OperandResult get(State state) {
        return OperandResult.make(
            state.getStack().isEmpty() ? null : state.getStack().top(),
            state);
      }
    };

  /**
   * Gets an operand that looks up a value in the dictionary without modifying
   * the matcher state.
   *
   * @param key The key to look up.
   * @return The corresponding operand.
   */
  @Nonnull
  public static Operand get(final Object key) {
    Preconditions.checkNotNull(key);
    return new Operand() {
      @Override
      public OperandResult get(State state) {
        return OperandResult.make(state.getDict().get(key), state);
      }
    };
  }
}
