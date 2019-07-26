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

package com.google.enterprise.secmgr.testing;

import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * A value expectation that uses a predicate to determine
 *
 * @param <T> The value's type.
 */
@Immutable
@ParametersAreNonnullByDefault
public class PredicateValueExpectation<T> extends AbstractValueExpectation<T> {
  @Nonnull protected final String description;
  @Nonnull protected final Predicate<T> predicate;

  protected PredicateValueExpectation(String description, Predicate<T> predicate) {
    Preconditions.checkNotNull(description);
    Preconditions.checkNotNull(predicate);
    this.description = description;
    this.predicate = predicate;
  }

  @Nonnull
  public static <V> PredicateValueExpectation<V> make(String description,
      Predicate<V> predicate) {
    return new PredicateValueExpectation<V>(description, predicate);
  }

  /**
   * Gets the description of the expected value.
   */
  @Nonnull
  public String getDescription() {
    return description;
  }

  /**
   * Gets the predicate for the expected value.
   */
  @Nonnull
  public Predicate<T> getPredicate() {
    return predicate;
  }

  @Override
  public String handleReturnValue(T returnValue) {
    if (predicate.apply(returnValue)) {
      return null;
    }
    return "Value was " + returnValue + " but expected " + description;
  }
}
