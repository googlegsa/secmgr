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
import com.google.common.base.Predicate;

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;

/**
 * Utilities for managing Unicode characters and strings.
 *
 */
@ParametersAreNonnullByDefault
public final class Unicode {
  /**
   * The upper limit, exclusive, of Unicode code points.
   */
  public static final int CODE_POINT_LIMIT = Character.MAX_CODE_POINT + 1;

  /**
   * The Unicode code point for CHARACTER TABULATION.
   */
  public static final int CHARACTER_TABULATION = 0x0009;

  /**
   * The Unicode code point for LINE FEED.
   */
  public static final int LINE_FEED = 0x000A;

  /**
   * The Unicode code point for LINE TABULATION.
   */
  public static final int LINE_TABULATION = 0x000B;

  /**
   * The Unicode code point for FORM FEED.
   */
  public static final int FORM_FEED = 0x000C;

  /**
   * The Unicode code point for CARRIAGE RETURN.
   */
  public static final int CARRIAGE_RETURN = 0x000D;

  /**
   * The Unicode code point for NEXT LINE.
   */
  public static final int NEXT_LINE = 0x0085;

  /**
   * The Unicode code point for LINE SEPARATOR.
   */
  public static final int LINE_SEPARATOR = 0x2028;

  /**
   * The Unicode code point for PARAGRAPH SEPARATOR.
   */
  public static final int PARAGRAPH_SEPARATOR = 0x2029;

  // Don't instantiate.
  private Unicode() {
    throw new UnsupportedOperationException();
  }

  /**
   * Is a given string a well-formed sequence of Unicode characters?  That is,
   * do all surrogates occur in proper pairs, and no noncharacters occur in the
   * string?
   *
   * @param string The string to test.
   * @return True only if the string is well formed.
   */
  public static boolean isWellFormed(String string) {
    for (int cp : new CodePointIterable(string)) {
      if (!isCharacter(cp)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Gets the length of a string in Unicode code points.
   *
   * @param string The string to take the length of.
   * @return The number of code points in the string.
   */
  @Nonnegative
  public static int length(String string) {
    int nChars = 0;
    for (int cp : new CodePointIterable(string)) {
      nChars += 1;
    }
    return nChars;
  }

  /**
   * Gets a Unicode code point from a string by index.
   *
   * @param string The string to get the code point from.
   * @param index The index of the code point.
   * @return The code point at that index.
   * @throws IllegalArgumentException if {@code index} is out of range.
   */
  @Nonnegative
  public static int get(String string, @Nonnegative int index) {
    Preconditions.checkArgument(index >= 0);
    int i = 0;
    for (int cp : new CodePointIterable(string)) {
      if (i == index) {
        return cp;
      }
      i += 1;
    }
    throw new IllegalArgumentException();
  }

  /**
   * Is a given integer a code point?
   *
   * @param n The integer to test.
   * @return True only if the integer is a code point.
   */
  public static boolean isCodePoint(int n) {
    return n >= 0 && n < CODE_POINT_LIMIT;
  }

  /**
   * Is a given integer a surrogate code point?
   *
   * @param cp The integer to test.
   * @return True only if the integer is a surrogate code point.
   */
  public static boolean isSurrogate(int cp) {
    return cp >= Character.MIN_SURROGATE && cp <= Character.MAX_SURROGATE;
  }

  /**
   * Is a given integer a scalar value?
   *
   * @param cp The integer to test.
   * @return True only if the integer is a scalar value.
   */
  public static boolean isScalarValue(int cp) {
    return isCodePoint(cp) && !isSurrogate(cp);
  }

  /**
   * Is a given integer a unicode character?  In other words, is it a scalar
   * value that's not a noncharacter?
   *
   * @param cp The integer to test.
   * @return True only if the integer is a unicode character.
   */
  public static boolean isCharacter(int cp) {
    return isScalarValue(cp)
        // These expressions identify the "noncharacter" values:
        && !((cp >= 0xFDD0 && cp < 0xFDF0) || (cp & 0xFFFE) == 0xFFFE);
  }

  /**
   * Is a given code point a Unicode line break?
   *
   * @param cp The code point to test.
   * @return True only if the code point is a line break.
   */
  public static boolean isLineBreak(int cp) {
    return cp == LINE_FEED || cp == FORM_FEED || cp == CARRIAGE_RETURN
        || cp == NEXT_LINE || cp == LINE_SEPARATOR || cp == PARAGRAPH_SEPARATOR;
  }

  /**
   * Is a given code point a Unicode whitespace character?
   *
   * @param cp The code point to test.
   * @return True only if the code point is whitespace.
   */
  public static boolean isWhitespace(int cp) {
    switch (Character.getType(cp)) {
      case Character.SPACE_SEPARATOR:
      case Character.LINE_SEPARATOR:
      case Character.PARAGRAPH_SEPARATOR:
        return true;
      case Character.CONTROL:
        switch (Character.getDirectionality(cp)) {
          case Character.DIRECTIONALITY_WHITESPACE:
          case Character.DIRECTIONALITY_SEGMENT_SEPARATOR:
          case Character.DIRECTIONALITY_PARAGRAPH_SEPARATOR:
            return true;
          default:
            return false;
        }
      default:
        return false;
    }
  }

  /**
   * A predicate for Unicode whitespace characters.
   *
   * @see #isWhitespace
   */
  @Nonnull public static final Predicate<Integer> WHITESPACE_PREDICATE =
      new Predicate<Integer>() {
        @Override
        public boolean apply(Integer cp) {
          return isWhitespace(cp);
        }
      };

  /**
   * Is a given code point a Unicode digit?
   *
   * @param cp The code point to test.
   * @return True only if the code point is a digit.
   */
  public static boolean isDigit(int cp) {
    return Character.getType(cp) == Character.DECIMAL_DIGIT_NUMBER;
  }

  /**
   * A predicate for Unicode digits.
   *
   * @see #isDigit
   */
  @Nonnull public static final Predicate<Integer> DIGIT_PREDICATE =
      new Predicate<Integer>() {
        @Override
        public boolean apply(Integer cp) {
          return isDigit(cp);
        }
      };
}
