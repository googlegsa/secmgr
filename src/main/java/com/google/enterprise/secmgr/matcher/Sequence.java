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
 * An implementation of a matcher that matches a list of matchers in order,
 * effectively matching the concatenation of the individual matches.  If any
 * component matcher fails, the composite matcher fails.
 * <p>
 * Equivalent to pattern concatenation in regular expressions.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
final class Sequence extends Matcher {
  @Nonnull private final ImmutableList<? extends Matcher> matchers;

  private Sequence(ImmutableList<? extends Matcher> matchers) {
    this.matchers = matchers;
  }

  /**
   * Gets a new sequence matcher.
   *
   * @param matchers The component matchers.
   * @return The corresponding sequence matcher.
   */
  @Nonnull
  static Matcher make(Iterable<? extends Matcher> matchers) {
    return new Sequence(ImmutableList.copyOf(matchers));
  }

  @Override
  protected Result match(State state, Succeed succeed, Fail fail) {
    return match2(state, succeed, fail, 0);
  }

  private Result match2(final State state, final Succeed succeed, Fail fail, final int index) {
    return (index < matchers.size())
        ? matchers.get(index).match(state,
            new Succeed() {
              @Override
              protected Result applyInternal(State state2, Fail fail2) {
                return match2(state2, succeed, fail2, index + 1);
              }
            },
            fail)
      : succeed.apply(state, fail);
  }
}
