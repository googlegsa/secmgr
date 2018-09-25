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

import com.google.common.base.Function;
import com.google.common.base.Preconditions;

import java.util.concurrent.Callable;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * A runnable test for functions.  Tests the function by calling it with a given
 * argument, then delegating to an {@link Expectation} to generate the test
 * result.
 *
 * @param <A1> The type of the argument to the function.
 * @param <V> The type of the function's value.
 */
@Immutable
@ParametersAreNonnullByDefault
public class FunctionTest<A1, V> extends CallableTest<V> {
  @Nonnull protected final Function<A1, V> function;
  @Nullable protected final A1 input;

  protected FunctionTest(final Function<A1, V> function, @Nullable final A1 input,
      Expectation<V> expectation) {
    super(
        new Callable<V>() {
          @Override
          public V call() {
            return function.apply(input);
          }
        },
        expectation);
    Preconditions.checkNotNull(function);
    this.function = function;
    this.input = input;
  }

  /**
   * Makes a new runnable test for a given function and input.
   *
   * @param <E1> The class of the function's inputs.
   * @param <U> The class of the function's outputs.
   * @param function The function to be tested.
   * @param input The input value to test the function with.
   * @param expectation The expected behavior of the function.
   */
  public static <E1, U> FunctionTest<E1, U> make(Function<E1, U> function, @Nullable E1 input,
      Expectation<U> expectation) {
    return new FunctionTest<E1, U>(function, input, expectation);
  }

  /**
   * Gets the function being tested.
   */
  @Nonnull
  public Function<A1, V> getFunction() {
    return function;
  }

  /**
   * Gets the input value that will be passed to the function during the test.
   */
  @Nullable
  public A1 getInput() {
    return input;
  }
}
