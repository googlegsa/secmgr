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

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * A runnable test for Callable objects.  Tests the callable by calling it, then
 * delegating to an {@link Expectation} to generate the test result.
 *
 * @param <V> The class of the callable's outputs.
 */
@Immutable
@ParametersAreNonnullByDefault
public class CallableTest<V> implements RunnableTest {
  @Nonnull protected final Callable<V> callable;
  @Nonnull protected final Expectation<V> expectation;

  /**
   * Make a new runnable test for a given callable.
   *
   * @param <T> The class of the callable's outputs.
   * @param callable The callable to be tested.
   * @param expectation The expected behavior of the callable.
   */
  @Nonnull
  public static <T> CallableTest<T> make(Callable<T> callable,
      Expectation<T> expectation) {
    Preconditions.checkNotNull(callable);
    Preconditions.checkNotNull(expectation);
    return new CallableTest<T>(callable, expectation);
  }

  protected CallableTest(Callable<V> callable, Expectation<V> expectation) {
    this.callable = callable;
    this.expectation = expectation;
  }

  /**
   * @return The callable to be tested.
   */
  @Nonnull
  public Callable<V> getCallable() {
    return callable;
  }

  /**
   * @return The expected behavior of the callable.
   */
  @Nonnull
  public Expectation<V> getExpectation() {
    return expectation;
  }

  @Override
  @Nullable
  public String runTest() {
    V actual;
    try {
      actual = callable.call();
    } catch (Exception e) {
      return expectation.handleException(e);
    }
    return expectation.handleReturnValue(actual);
  }
}
