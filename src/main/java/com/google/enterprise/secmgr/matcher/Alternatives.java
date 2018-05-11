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

import com.google.common.collect.ImmutableList;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * An implementation of a matcher that tries different alternatives, in order,
 * until one matches.  If any component matcher succeeds, the composite matcher
 * succeeds.
 * <p>
 * If one of the component matchers succeeds, it sets up a failure point (for
 * back-tracking) that will continue trying the remaining component matchers.
 * <p>
 * Equivalent to the "|" operator in regular expressions.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
final class Alternatives extends Matcher {
  @Nonnull private final ImmutableList<? extends Matcher> matchers;

  private Alternatives(ImmutableList<? extends Matcher> matchers) {
    this.matchers = matchers;
  }

  /**
   * Gets a new alternatives matcher.
   *
   * @param matchers The component matchers that are the alternatives to try.
   * @return The corresponding alternatives matcher.
   */
  @Nonnull
  static Matcher make(Iterable<? extends Matcher> matchers) {
    return new Alternatives(ImmutableList.copyOf(matchers));
  }

  @Override
  protected Result match(State state, Succeed succeed, Fail fail) {
    return match2(state, succeed, fail, 0);
  }

  private Result match2(final State state, final Succeed succeed, final Fail fail,
      final int index) {
    return (index < matchers.size())
        ? matchers.get(index).match(state, succeed,
            new Fail() {
              @Override
              protected Result applyInternal() {
                return match2(state, succeed, fail, index + 1);
              }
            })
        : fail.apply();
  }
}
