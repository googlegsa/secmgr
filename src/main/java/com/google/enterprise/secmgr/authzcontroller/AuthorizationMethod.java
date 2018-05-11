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
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.modules.AuthzResult;

import java.util.Collection;

/**
 * A mechanism for doing authorization. Send in some queries and an identity and
 * it gives you back decisions.
 */
public interface AuthorizationMethod {

  /**
   * Gets an authorization decision for a given set of resources.
   *
   * @param resources The resources to be authorized.
   * @param snapshot A session snapshot to get credentials from.
   * @return A set of authorization results.
   */
  public AuthzResult authorize(Collection<Resource> resources, SessionSnapshot snapshot);

  /**
   * A tag that identifies this method. For testing, this tag is used to judge
   * equality, so for testability, it's important for implementors to choose
   * unique names.  In normal operation, this is unused.
   *
   * @return The name of this method.
   */
  public String getName();

  /**
   * The timeout value(in milliseconds) for this authorization method. So that the caller
   * can set the correct timeout value during dispatch.
   */
  public int getTimeout();
}
