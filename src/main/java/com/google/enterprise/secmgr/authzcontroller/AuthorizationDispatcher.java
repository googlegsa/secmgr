// Copyright 2009 Google Inc.
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

package com.google.enterprise.secmgr.authzcontroller;

import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.modules.AuthzResult;

import java.util.Collection;

/**
 * A dispatcher that takes a collection of authorization batches and processes
 * them, returning a composite result.
 */
public interface AuthorizationDispatcher {
  public AuthzResult dispatch(Collection<AuthzBatch> batches, SessionSnapshot snapshot);
}
