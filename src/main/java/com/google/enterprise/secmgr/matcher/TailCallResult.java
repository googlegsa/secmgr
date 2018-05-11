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

import javax.annotation.Nonnull;

/**
 * A matcher result that is used to simulate tail recursion.  Instead of
 * directly calling a continuation, the matcher returns a tail-call result that
 * knows how to call the continuation, and the top-level matcher receives the
 * result and tells it to call the continuation.  This eliminates the
 * building-up of control stack when calling continuations.
 *
 */
interface TailCallResult extends Result {
  /**
   * Calls the continuation represented by this result.
   */
  @Nonnull Result call();
}
