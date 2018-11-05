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

import com.google.common.base.Preconditions;

import javax.annotation.concurrent.Immutable;

/**
 * An expectation that expects the computation to throw an exception of a
 * specified type.
 *
 * @param <T> The type of value that should be returned.
 */
@Immutable
public class SimpleExceptionExpectation<T> implements Expectation<T> {

  private final Class<? extends Exception> expectedExceptionClass;

  protected SimpleExceptionExpectation(Class<? extends Exception> expectedExceptionClass) {
    this.expectedExceptionClass = expectedExceptionClass;
  }

  /**
   * Make a new instance of this type.
   *
   * @param expectedExceptionClass The class of exceptions that are are to be expected.
   * @return A new instance that accepts the given exception type.
   */
  public static <T> SimpleExceptionExpectation<T> make(
      Class<? extends Exception> expectedExceptionClass) {
    Preconditions.checkNotNull(expectedExceptionClass);
    return new SimpleExceptionExpectation<T>(expectedExceptionClass);
  }

  /**
   * @return The expected exception class given when this object was created.
   */
  public Class<? extends Exception> getExpectedExceptionClass() {
    return expectedExceptionClass;
  }

  @Override
  public String handleReturnValue(T returnValue) {
    return "Expected exception, but got value: " + returnValue;
  }

  @Override
  public String handleException(Exception e) {
    if (expectedExceptionClass.isInstance(e)) {
      return null;
    }
    return "Exception of unexpected type: "
        + e.getClass().getName()
        + "; "
        + e.getMessage();
  }
}
