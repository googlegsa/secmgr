// Copyright 2010 Google Inc.
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

import com.google.common.base.Predicate;

import java.util.Objects;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * An expectation for a simple return value.  Compares the returned value for
 * equality with a given expected value.
 *
 * @param <T> The value's type.
 */
@Immutable
@ParametersAreNonnullByDefault
public final class EqualValueExpectation<T> extends PredicateValueExpectation<T> {
  @Nullable private final T expectedValue;

  protected EqualValueExpectation(@Nullable final T expectedValue) {
    super((expectedValue == null) ? "null" : expectedValue.toString(),
        new Predicate<T>() {
          @Override
          public boolean apply(T returnValue) {
            return Objects.equals(expectedValue, returnValue);
          }
        });
    this.expectedValue = expectedValue;
  }

  public static <V> EqualValueExpectation<V> make(@Nullable V expectedValue) {
    return new EqualValueExpectation<V>(expectedValue);
  }

  /**
   * Gets the expected value given when this object was created.
   */
  @Nullable
  public T getExpectedValue() {
    return expectedValue;
  }
}
