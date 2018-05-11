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
 * A simple object that holds a matcher's state.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
public final class State {
  // Our position in the input sequence.
  @Nonnull private final Position position;
  // A stack of values created by the matching process.  This could be used to
  // match two instances of the same character in a row, for example, by pushing
  // the first matched character, and popping it to match the second.
  @Nonnull private final ValueStack stack;
  // A collection of named values created by the matching process.  This could
  // be used to hold something like a named regexp group, for example.
  @Nonnull private final Dict dict;

  private State(Position position, ValueStack stack, Dict dict) {
    this.position = position;
    this.stack = stack;
    this.dict = dict;
  }

  /**
   * Makes a state object.
   *
   * @param position A position.
   * @param stack A value stack.
   * @param dict A dictionary.
   * @return The corresponding state object.
   */
  @Nonnull
  public static State make(Position position, ValueStack stack, Dict dict) {
    Preconditions.checkNotNull(position);
    Preconditions.checkNotNull(stack);
    Preconditions.checkNotNull(dict);
    return new State(position, stack, dict);
  }

  /**
   * Gets the position.
   */
  @Nonnull
  public Position getPosition() {
    return position;
  }

  /**
   * Gets a new state in which the position has been changed.
   *
   * @param position The new position.
   * @return A new state with the given position.
   */
  @Nonnull
  public State newPosition(Position position) {
    Preconditions.checkNotNull(position);
    return new State(position, stack, dict);
  }

  /**
   * Gets the value stack.
   */
  @Nonnull
  public ValueStack getStack() {
    return stack;
  }

  /**
   * Gets a new state in which the stack has been changed.
   *
   * @param stack The new stack.
   * @return A new state with the given stack.
   */
  @Nonnull
  public State newStack(ValueStack stack) {
    Preconditions.checkNotNull(stack);
    return new State(position, stack, dict);
  }

  /**
   * Gets the dictionary.
   */
  @Nonnull
  public Dict getDict() {
    return dict;
  }

  /**
   * Gets a new state in which the dictionary has been changed.
   *
   * @param dict The new dictionary.
   * @return A new state with the given dict.
   */
  @Nonnull
  public State newDict(Dict dict) {
    Preconditions.checkNotNull(dict);
    return new State(position, stack, dict);
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append("{position: ");
    builder.append(position.toString());
    builder.append(", stack: ");
    builder.append(stack.toString());
    builder.append(", dict: ");
    builder.append(dict.toString());
    builder.append("}");
    return builder.toString();
  }
}
