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
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * An implementation of "character sets".  Unlike the other implementations I've
 * seen, this one handles the full Unicode character set.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
public final class CharSet {
  public static final CharSet NONE = builder().build();
  public static final CharSet ALL = builder().add(0, Unicode.CODE_POINT_LIMIT).build();
  public static final CharSet US_ASCII = builder().add(0, 0x80).build();

  // This array holds the ranges of code points that are members of the set.
  // It's arranged as a sorted array of inclusive-low/exclusive-high pairs, with
  // no empty ranges and no overlaps.  Consequently the elements of the array
  // are guaranteed to be non-negative and monotonically increasing.  We use
  // this encoding because it's the smallest one I can think of, and because it
  // guarantees locality of reference during operations on the array.  Using two
  // arrays uses about the same space, but doesn't guarantee locality of
  // reference.
  @Nonnull private final int[] packedRanges;

  private CharSet(int[] packedRanges) {
    this.packedRanges = packedRanges;
  }

  @Nonnull
  private int[] getPackedRanges() {
    return packedRanges;
  }

  /**
   * Is the given Unicode code point a member of this character set?
   *
   * @param cp The code point to test.
   * @return True only if {@code cp} is a member.
   */
  public boolean isMember(int cp) {
    return Unicode.isCharacter(cp) && isMemberInternal(cp);
  }

  // This binary search is probably too clever.  Since packedRanges is an array
  // of inclusive-low/exclusive-high code-point bounds, the search must treat
  // each pair as a range, which means that start, end, and mid must always be
  // even.  And we're not checking for equality of the code point to an element
  // of an array; instead we're checking whether the code point is inside one of
  // the ranges.  But aside from these details, it's a standard binary search.
  private boolean isMemberInternal(int cp) {
    int start = 0;
    int end = packedRanges.length;
    while (start < end) {
      // Make sure mid is even:
      int mid = ((start + end) / 4) * 2;
      if (cp < packedRanges[mid]) {
        end = mid;
      } else if (cp >= packedRanges[mid + 1]) {
        start = mid + 2;
      } else {
        return true;
      }
    }
    return false;
  }

  /**
   * Gets a predicate that performs {@link #isMember} on this character set.
   */
  @Nonnull
  public Predicate<Integer> isMemberPredicate() {
    return new Predicate<Integer>() {
      @Override
      public boolean apply(Integer cp) {
        return isMember(cp);
      }
    };
  }

  /**
   * Gets the code points contained in this character set, returning them as a
   * list of non-empty ranges.  No two of the ranges intersect one another, and
   * the ranges are ordered from smaller code points to larger ones.
   */
  @Nonnull
  public ImmutableList<Range> getRanges() {
    ImmutableList.Builder<Range> builder = ImmutableList.builder();
    for (int i = 0; i < packedRanges.length; i += 2) {
      builder.add(Range.make(packedRanges[i], packedRanges[i + 1]));
    }
    return builder.build();
  }

  /**
   * A non-empty range of Unicode code points.
   */
  @Immutable
  public static final class Range implements Comparable<Range> {
    @Nonnegative private final int low;
    @Nonnegative private final int high;

    private Range(@Nonnegative int low, @Nonnegative int high) {
      this.low = low;
      this.high = high;
    }

    /**
     * Gets a new range.
     *
     * @param low The lower limit, inclusive, of the code points in the range.
     * @param high The upper limit, exclusive, of the code points in the range.
     * @return A new range with those limits.
     * @throws IllegalArgumentException if {@code low} is negative or if
     *     {@code high} is less than or equal to {@code low}.
     */
    @Nonnull
    public static Range make(@Nonnegative int low, @Nonnegative int high) {
      Preconditions.checkArgument(low >= 0 && low < high && high <= Unicode.CODE_POINT_LIMIT);
      return new Range(low, high);
    }

    /**
     * Gets the lower limit (inclusive) of the range.
     */
    @Nonnegative
    public int getLow() {
      return low;
    }

    /**
     * Gets the upper limit (exclusive) of the range.
     */
    @Nonnegative
    public int getHigh() {
      return high;
    }

    @Override
    public int compareTo(Range other) {
      if (low < other.low) { return -1; }
      if (low > other.low) { return 1; }
      if (high < other.high) { return -1; }
      if (high > other.high) { return 1; }
      return 0;
    }

    @Override
    public boolean equals(Object object) {
      if (object == this) { return true; }
      if (!(object instanceof Range)) { return false; }
      Range other = (Range) object;
      return low == other.low && high == other.high;
    }

    @Override
    public int hashCode() {
      return Objects.hash(low, high);
    }

    @Override
    public String toString() {
      return "Range:[" + low + ", " + high + ")";
    }
  }

  @Override
  public boolean equals(Object object) {
    if (object == this) { return true; }
    if (!(object instanceof CharSet)) { return false; }
    CharSet other = (CharSet) object;
    return Arrays.equals(packedRanges, other.packedRanges);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(packedRanges);
  }

  // **************** Constructors ****************

  /**
   * Gets a character set containing only the characters in a given string.
   *
   * @param string The string containing the characters to use.
   * @return A character set containing only those characters.
   */
  @Nonnull
  public static CharSet make(String string) {
    return builder().add(string).build();
  }


  /**
   * Gets a character-set builder.
   */
  @Nonnull
  public static Builder builder() {
    return new Builder();
  }

  /**
   * A factory class for building character sets.
   */
  @NotThreadSafe
  @ParametersAreNonnullByDefault
  public static final class Builder {
    private final List<Range> ranges;

    private Builder() {
      ranges = Lists.newArrayList();
    }

    /**
     * Adds a code point to the character set being built.
     *
     * @param cp The code point to be added.
     * @return This builder, for convenience.
     */
    @Nonnull
    public Builder add(@Nonnegative int cp) {
      ranges.add(Range.make(cp, cp + 1));
      return this;
    }

    /**
     * Adds a range of code points to the character set being built.
     *
     * @param low The lower limit of the range, inclusive.
     * @param high The upper limit of the range, exclusive.
     * @return This builder, for convenience.
     */
    @Nonnull
    public Builder add(@Nonnegative int low, @Nonnegative int high) {
      ranges.add(Range.make(low, high));
      return this;
    }

    /**
     * Adds the characters in a given string to the character set being built.
     *
     * @param string The string containing the element characters.
     * @return This builder, for convenience.
     */
    @Nonnull
    public Builder add(String string) {
      for (int cp : new CodePointIterable(string)) {
        if (!Unicode.isCharacter(cp)) {
          throw new IllegalArgumentException();
        }
        ranges.add(Range.make(cp, cp + 1));
      }
      return this;
    }

    /**
     * Adds the characters in a given range to the character set being built.
     *
     * @param range The range to be added.
     * @return This builder, for convenience.
     */
    @Nonnull
    public Builder add(Range range) {
      Preconditions.checkNotNull(range);
      ranges.add(range);
      return this;
    }

    /**
     * Adds the characters in some given ranges to the character set being
     * built.
     *
     * @param ranges The ranges to be added.
     * @return This builder, for convenience.
     */
    @Nonnull
    public Builder addAll(Collection<Range> ranges) {
      Preconditions.checkNotNull(ranges);
      this.ranges.addAll(ranges);
      return this;
    }

    @Nonnull
    public CharSet build() {
      return make(ranges);
    }
  }

  @Nonnull
  private static CharSet make(List<Range> ranges) {
    Collections.sort(ranges);
    if (!ranges.isEmpty()) {
      int prevLow = ranges.get(0).getLow();
      int prevHigh = ranges.get(0).getHigh();
      int i = 1;
      while (i < ranges.size()) {
        int low = ranges.get(i).getLow();
        int high = ranges.get(i).getHigh();
        if (low > prevHigh) {
          // This pair is disjoint from the previous one.
          prevLow = low;
          prevHigh = high;
          i += 1;
        } else {
          // This pair overlaps or abuts the previous one.
          // No need to change prevLow since it's guaranteed <= low.
          prevHigh = Math.max(prevHigh, high);
          ranges.set(i - 1, Range.make(prevLow, prevHigh));
          ranges.remove(i);
        }
      }
    }
    return new CharSet(packRanges(ranges));
  }

  private static int[] packRanges(List<Range> ranges) {
    int[] packedRanges = new int[ranges.size() * 2];
    int i = 0;
    for (Range range : ranges) {
      packedRanges[i++] = range.getLow();
      packedRanges[i++] = range.getHigh();
    }
    return packedRanges;
  }

  // **************** Combiners ****************

  /**
   * Gets the set union of some given character sets.
   *
   * @param sets The character sets to combine.
   * @return A new character set containing every character that appears in at
   *     least one of the {@code sets}.
   */
  @Nonnull
  public static CharSet union(CharSet... sets) {
    if (sets.length == 0) {
      return NONE;
    }
    CharSet result = sets[0];
    int i = 1;
    while (i < sets.length) {
      result = operate(UNION, result, sets[i++]);
    }
    return result;
  }

  /**
   * Gets the set intersection of some given character sets.
   *
   * @param sets The character sets to combine.
   * @return A new character set containing every character that appears in all
   *     of the {@code sets}.
   */
  @Nonnull
  public static CharSet intersection(CharSet... sets) {
    if (sets.length == 0) {
      return NONE;
    }
    CharSet result = sets[0];
    int i = 1;
    while (i < sets.length) {
      result = operate(INTERSECTION, result, sets[i++]);
    }
    return result;
  }

  /**
   * Gets the set difference of two character sets.
   *
   * @param set1 The base character set.
   * @param set2 The character set to be subtracted from {@code set1}.
   * @return A new character set containing every character in {@code set1} that
   *     does not appear in {@code set2}.
   */
  @Nonnull
  public static CharSet difference(CharSet set1, CharSet set2) {
    return operate(DIFFERENCE, set1, set2);
  }

  /**
   * Subtracts a given character set from this one.
   *
   * @param set The character set to be subtracted from this set.
   * @return A new character set containing every character in this set that
   *     does not appear in {@code set}.
   */
  @Nonnull
  public CharSet subtract(CharSet set) {
    return operate(DIFFERENCE, this, set);
  }

  /**
   * Gets the set inverse of this character set.
   *
   * @return A new character set containing all Unicode characters that don't
   *     appear in this set.
   */
  @Nonnull
  public CharSet invert() {
    return operate(DIFFERENCE, ALL, this);
  }

  private interface Operation {
    public boolean apply(boolean b1, boolean b2);
  }

  private static final Operation UNION =
      new Operation() {
        @Override
        public boolean apply(boolean b1, boolean b2) {
          return b1 || b2;
        }
      };

  private static final Operation INTERSECTION =
      new Operation() {
        @Override
        public boolean apply(boolean b1, boolean b2) {
          return b1 && b2;
        }
      };

  private static final Operation DIFFERENCE =
      new Operation() {
        @Override
        public boolean apply(boolean b1, boolean b2) {
          return b1 && !b2;
        }
      };

  // Another too-clever algorithm.  This treats the packedRanges of two given
  // character sets as digital signals, and combines them into the packedRanges
  // of the result using a binary operation.  Basically, each time the index
  // into one of the inputs is incremented, it toggles the "signal", where a
  // signal level of zero means that the code points in that area are NOT part
  // of the set, and a signal level of one means code points in that area ARE
  // part of the set.  So we walk down the two arrays in order, keeping track of
  // the signals in the b1 and b2 variables, and then use those variables as
  // input to the binary operation.
  @Nonnull
  private static CharSet operate(Operation operation, CharSet set1, CharSet set2) {
    // Input signal one.
    int[] s1 = set1.getPackedRanges();
    // Input signal two.
    int[] s2 = set2.getPackedRanges();
    // Output signal.
    int[] s3 = new int[s1.length + s2.length];
    // The index into s1
    int i1 = 0;
    // The "signal value" of s1 at the current index.
    boolean b1 = false;
    // The index into s2.
    int i2 = 0;
    // The "signal value" of s2 at the current index.
    boolean b2 = false;
    // The index into s3.
    int i3 = 0;
    // The "signal value" of s3 at the current index.
    boolean b3 = false;
    while (i1 < s1.length || i2 < s2.length) {
      int p;
      if (i2 == s2.length || s1[i1] < s2[i2]) {
        // The next transition is in s1, so get the transition point p,
        // increment i1, and flip b1.
        p = s1[i1++];
        b1 = !b1;
      } else if (i1 == s1.length || s1[i1] > s2[i2]) {
        // The next transition is in s2, so get the transition point p,
        // increment i2, and flip b2.
        p = s2[i2++];
        b2 = !b2;
      } else {
        // Both inputs have an identical transition.  Get the transition point
        // from one of them, increment both indexes, and flip both bits.
        p = s1[i1];
        i1 += 1;
        b1 = !b1;
        i2 += 1;
        b2 = !b2;
      }
      // Apply the operation.
      boolean b = operation.apply(b1, b2);
      if (b != b3) {
        // The resulting value differs from what we last emitted, so emit
        // another transition point, increment i3, and flip b3.
        s3[i3++] = p;
        b3 = b;
      }
    }
    if (b3) {
      // We've run out of inputs but haven't closed the last output range.
      if (s3[i3 - 1] < Unicode.CODE_POINT_LIMIT) {
        // If the last output range started before CODE_POINT_LIMIT, it ends at
        // CODE_POINT_LIMIT.
        s1[i3++] = Unicode.CODE_POINT_LIMIT;
      } else {
        // If the last output range started at CODE_POINT_LIMIT, just delete it.
        i3 -= 1;
      }
    }
    // Truncate the output array to the correct length.
    return new CharSet(truncate(s3, i3));
  }

  @Nonnull
  private static int[] truncate(int[] packedRanges, int i) {
    return (i < packedRanges.length) ? Arrays.copyOf(packedRanges, i) : packedRanges;
  }
}
