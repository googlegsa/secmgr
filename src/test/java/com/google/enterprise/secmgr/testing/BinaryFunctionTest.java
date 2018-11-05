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

import java.util.concurrent.Callable;
import java.util.function.BiFunction;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * A runnable test for functions.  Tests the function by calling it with a given
 * argument, then delegating to an {@link Expectation} to generate the test
 * result.
 *
 * @param <A1> The type of the first argument to the function.
 * @param <A2> The type of the second argument to the function.
 * @param <V> The type of the function's value.
 */
@Immutable
@ParametersAreNonnullByDefault
public class BinaryFunctionTest<A1, A2, V> extends CallableTest<V> {
  @Nonnull protected final BiFunction<A1, A2, V> function;
  @Nullable protected final A1 a1;
  @Nullable protected final A2 a2;

  protected BinaryFunctionTest(final BiFunction<A1, A2, V> function, @Nullable final A1 a1,
      @Nullable final A2 a2, Expectation<V> expectation) {
    super(
        new Callable<V>() {
          @Override
          public V call() {
            return function.apply(a1, a2);
          }
        },
        expectation);
    Preconditions.checkNotNull(function);
    this.function = function;
    this.a1 = a1;
    this.a2 = a2;
  }

  /**
   * Makes a new runnable test for a given function and input.
   *
   * @param <E1> The type of the first argument to the function.
   * @param <E2> The type of the second argument to the function.
   * @param <U> The type of the function's value.
   * @param function The function to be tested.
   * @param a1 The first argument to pass to the function.
   * @param a2 The second argument to pass to the function.
   * @param expectation The expected behavior of the function.
   */
  @Nonnull
  public static <E1, E2, U> BinaryFunctionTest<E1, E2, U> make(
      BiFunction<E1, E2, U> function, @Nullable E1 a1, @Nullable E2 a2,
      Expectation<U> expectation) {
    return new BinaryFunctionTest<E1, E2, U>(function, a1, a2, expectation);
  }

  /**
   * Gets the function being tested.
   */
  @Nonnull
  public BiFunction<A1, A2, V> getFunction() {
    return function;
  }

  /**
   * Gets the first input value that will be passed to the function during the
   * test.
   */
  @Nullable
  public A1 getArg1() {
    return a1;
  }

  /**
   * Gets the second input value that will be passed to the function during the
   * test.
   */
  @Nullable
  public A2 getArg2() {
    return a2;
  }
}
