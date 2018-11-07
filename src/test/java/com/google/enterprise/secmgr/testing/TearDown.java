// Copyright 2018 Google Inc.
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

@FunctionalInterface
public interface TearDown {
  /**
   * Performs a <b>single</b> tear-down operation.
   *
   * <p>A failing {@link TearDown} may or may not fail a tl4j test, depending on the version of
   * JUnit test case you are running under.
   *
   * <p>tl4j details: For backwards compatibility, {@code junit3.TearDownTestCase} currently does
   * not fail a test when an exception is thrown from one of its {@link TearDown} instances, but
   * this is subject to change. Also, {@code junit4.TearDownTestCase} will.
   *
   * @throws Exception for any reason. {@code TearDownTestCase} ensures that any exception thrown
   *     will not interfere with other TearDown operations.
   */
  void tearDown() throws Exception;
}