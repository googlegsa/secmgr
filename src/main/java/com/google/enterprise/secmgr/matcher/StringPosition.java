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

import java.util.Objects;

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * An implementation of an input sequence that is backed by a string.
 * <p>
 * Java doesn't support the full Unicode character set properly.  The char type
 * is a 16-bit unsigned type, while Unicode has a 21-bit space of "scalar
 * values", which correspond roughly to what most people would call characters.
 * So Java fakes it by using the UTF-16 encoding in strings, which encodes
 * scalar values larger than 16 bits as "surrogate pairs" of code points.
 * <p>
 * The hackery here looks for and decodes those surrogate pairs to produce a
 * sequence of scalar values.  I deliberately chose to call the "code points",
 * since that's the (incorrect) terminology used by Java, and it seemed best to
 * be consistent.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
final class StringPosition implements Position {
  @Nonnull private final String string;
  @Nonnegative private final int index;

  private StringPosition(String string, @Nonnegative int index) {
    this.string = string;
    this.index = index;
  }

  /**
   * Gets a new string position.
   *
   * @param string The string that is the input sequence to use.
   * @return The initial position in that string.
   * @throws IllegalArgumentException if the string isn't well formed.
   */
  @Nonnull
  static Position make(String string) {
    Preconditions.checkArgument(Unicode.isWellFormed(string));
    return new StringPosition(string, 0);
  }

  @Override
  public boolean hasChar() {
    return index < string.length();
  }

  @Override
  public boolean hasPrevChar() {
    return index > 0;
  }

  @Override
  public boolean hasChars(int nChars) {
    Preconditions.checkArgument(nChars >= 0);
    int i = index;
    int j = 0;
    while (j < nChars && i < string.length()) {
      i = string.offsetByCodePoints(i, 1);
      j += 1;
    }
    return j == nChars;
  }

  @Override
  public int getChar() {
    if (!hasChar()) { throw new IndexOutOfBoundsException(); }
    return string.codePointAt(index);
  }

  @Override
  public int getPrevChar() {
    if (!hasPrevChar()) { throw new IndexOutOfBoundsException(); }
    return string.codePointBefore(index);
  }

  @Override
  public String getString(int nChars) {
    if (!hasChars(nChars)) { throw new IndexOutOfBoundsException(); }
    return string.substring(index, string.offsetByCodePoints(index, nChars));
  }

  @Override
  public String getString(Position start) {
    StringPosition p = StringPosition.class.cast(start);
    Preconditions.checkArgument(string.equals(p.string) && p.index <= index);
    return string.substring(p.index, index);
  }

  @Override
  public int countChars() {
    return countChars(0);
  }

  @Override
  public int countChars(Position start) {
    StringPosition p = StringPosition.class.cast(start);
    Preconditions.checkArgument(string.equals(p.string) && p.index <= index);
    return countChars(p.index);
  }

  @Nonnegative
  private int countChars(@Nonnegative int startIndex) {
    int i = startIndex;
    int j = 0;
    while (i < index) {
      i = string.offsetByCodePoints(i, 1);
      j += 1;
    }
    Preconditions.checkState(i == index);
    return j;
  }

  @Override
  public Position nextPosition() {
    if (!hasChar()) { throw new IndexOutOfBoundsException(); }
    return new StringPosition(string, string.offsetByCodePoints(index, 1));
  }

  @Override
  public Position nextPosition(int nChars) {
    if (!hasChars(nChars)) { throw new IndexOutOfBoundsException(); }
    return new StringPosition(string, string.offsetByCodePoints(index, nChars));
  }

  @Override
  public boolean equals(Object object) {
    if (object == this) { return true; }
    if (!(object instanceof StringPosition)) { return false; }
    StringPosition other = (StringPosition) object;
    return string.equals(other.string) && index == other.index;
  }

  @Override
  public int hashCode() {
    return Objects.hash(string, index);
  }

  @Override
  public String toString() {
    return "{StringPosition string=\"" + string + "\"; index=" + index + "}";
  }
}
