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
 * A wrapper that wraps a matcher and will match the same matcher against the
 * input sequence a specified number of times.  This matcher matches greedily,
 * meaning that it matches the maximum number of times, and then decreases the
 * number of repeats as needed.
 * <p>
 * Equivalent to the "*", "+", "?", and "{N,M}" operators in regular
 * expressions.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
final class GreedyRepeater extends Matcher {
  @Nonnull private final Matcher matcher;
  @Nonnegative private final int min;
  @Nonnegative private final int max;

  private GreedyRepeater(Matcher matcher, @Nonnegative int min, @Nonnegative int max) {
    Preconditions.checkNotNull(matcher);
    Preconditions.checkArgument(min >= 0);
    Preconditions.checkArgument(max >= min);
    this.matcher = matcher;
    this.min = min;
    this.max = max;
  }

  /**
   * Gets a greedy repeated matcher by wrapping a given matcher.
   *
   * @param matcher The matcher that is being wrapped.
   * @param min The minimum number of times the wrapped matcher must match for
   *     the repeated match to be considered successful.
   * @param max The maximum number of times the wrapped matcher must match for
   *     the repeated match to be considered successful.  Use
   *     {@code Integer.MAX_VALUE} to mean "no maximum".
   * @return The corresponding wrapped matcher.
   */
  @Nonnull
  static Matcher make(Matcher matcher, @Nonnegative int min, @Nonnegative int max) {
    return new GreedyRepeater(matcher, min, max);
  }

  @Override
  protected Result match(State state, Succeed succeed, Fail fail) {
    return match1(state, succeed, fail, 0);
  }

  private Result match1(final State state, final Succeed succeed, final Fail fail,
      @Nonnegative final int nMatched) {
    if (nMatched < min) {
      return matcher.match(state,
          new Succeed() {
            @Override
            protected Result applyInternal(State state2, Fail fail2) {
              return match1(state2, succeed, fail2, nMatched + 1);
            }
          },
          fail);
    }
    if (nMatched < max) {
      return matcher.match(state,
          new Succeed() {
            @Override
            protected Result applyInternal(State state2, Fail fail2) {
              // If the matcher didn't make any progress, we're finished.
              return state.getPosition().equals(state2.getPosition())
                  ? fail2.apply()
                  : match1(state2, succeed, fail2, nMatched + 1);
            }
          },
          new Fail() {
            @Override
            protected Result applyInternal() {
              return succeed.apply(state, fail);
            }
          });
    }
    return succeed.apply(state, fail);
  }
}
