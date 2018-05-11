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

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;

/**
 * An abstraction of a sequence of Unicode scalar values that is fed as input to
 * a matcher.  A position is a pointer into a stream of input characters; it
 * points between two characters in the sequence.  The initial position precedes
 * the first character in the sequence, while the final position follows the
 * last character in the sequence.
 * <p>
 * The input sequence is guaranteed not to contain Unicode noncharacters.
 *
 */
@ParametersAreNonnullByDefault
public interface Position {
  /**
   * Does this position have a following character?
   *
   * @return True only if there's a following character.  False if this is the
   *     last position in the input sequence.
   */
  public boolean hasChar();

  /**
   * Does this position have a preceding character?
   *
   * @return True only if there's a preceding character.  False if this is the
   *     first position in the input sequence.
   */
  public boolean hasPrevChar();

  /**
   * Does this position have a specified number of following characters?
   *
   * @param nChars The number of characters to test for.
   * @return True only if there are {@code nChars} following characters.
   */
  public boolean hasChars(@Nonnegative int nChars);

  /**
   * Gets the character following this position.
   *
   * @return The following character as a Unicode code point.
   * @throws IndexOutOfBoundsException if there is no following character.
   */
  public int getChar();

  /**
   * Gets the character preceding this position.
   *
   * @return The preceding character as a Unicode code point.
   * @throws IndexOutOfBoundsException if there is no preceding character.
   */
  public int getPrevChar();

  /**
   * Gets a specified number of characters following this position.
   *
   * @param nChars The number of characters to get.
   * @return The following characters as a string.
   * @throws IndexOutOfBoundsException if there aren't enough following
   *     characters.
   */
  @Nonnull
  public String getString(@Nonnegative int nChars);

  /**
   * Gets all the characters starting at a given position and ending at this
   * position.
   *
   * @param startPosition The position at which to start getting characters.
   * @return The specified character range as a string.
   * @throws IllegalArgumentException if {@code startPosition} doesn't precede
   *     this position.
   */
  @Nonnull
  public String getString(Position startPosition);

  /**
   * Counts the characters starting at the initial position and ending at this
   * position.
   */
  @Nonnegative
  public int countChars();

  /**
   * Counts the characters starting at a given position and ending at this
   * position.
   *
   * @param startPosition The position at which to start getting characters.
   * @return The number of characters between the two positions.
   * @throws IllegalArgumentException if {@code startPosition} doesn't precede
   *     this position.
   */
  @Nonnegative
  public int countChars(Position startPosition);

  /**
   * Gets the next position in the input sequence.  The returned position is on
   * the other side of the character following this position; that same
   * character precedes the returned position.
   *
   * @return The next position.
   * @throws IndexOutOfBoundsException if this is the final position in the
   *     input sequence.
   */
  @Nonnull
  public Position nextPosition();

  /**
   * Gets the input-sequence position a given number of characters forward from
   * this one.
   *
   * @param nChars The number of characters to move forward.
   * @return The specified position.
   * @throws IndexOutOfBoundsException if there aren't that many characters left
   *     in the input sequence.
   */
  @Nonnull
  public Position nextPosition(@Nonnegative int nChars);
}
