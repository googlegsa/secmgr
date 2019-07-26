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

/**
 * An expectation represents the expected result of a computation.  It is
 * responsible for deciding whether a computation's result is expected or
 * unexpected, and if unexpected to provide a reason why.
 *
 * @param <T> The type returned by the computation, if it returns.
 */
public interface Expectation<T> {

  /**
   * If the computation under test returns a value, this method is called with
   * the value as an argument.
   *
   * @param returnValue The value returned by the computation under test.
   * @return Null if the returned value is what was expected, or a descriptive
   *     string if it was not.
   */
  public String handleReturnValue(T returnValue);

  /**
   * If the computation under test throws an exception, this method is called
   * with the thrown exception as an argument.
   *
   * @param e The exception that was shown.
   * @return Null if the exception is what was expected, or a descriptive string
   *     if it was not.
   */
  public String handleException(Exception e);
}
