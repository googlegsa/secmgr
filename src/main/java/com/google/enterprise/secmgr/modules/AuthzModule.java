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

package com.google.enterprise.secmgr.modules;

import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.FlexAuthzRule;

import java.io.IOException;
import java.util.Collection;

/**
 * An authorization module determines whether some given credentials are
 * sufficient to allow access to a given collection of resources.
 */
public interface AuthzModule {
  /**
   * Authorize resources using a given set of credentials.
   *
   * @param resources The resources being tested.
   * @param view A session view to get credentials from.
   * @param rule An authorization rule for this module.
   * @return The results, determining the access permissions for each of the resources.
   */
  public AuthzResult authorize(Collection<Resource> resources, SessionView view,
      FlexAuthzRule rule)
      throws IOException;
}
