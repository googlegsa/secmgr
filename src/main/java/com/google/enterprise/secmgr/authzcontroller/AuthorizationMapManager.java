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

package com.google.enterprise.secmgr.authzcontroller;

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;

/**
 * An authorization map manager is the program responsible for managing the
 * authorization map.  It provides a single operation, to get the current
 * authorization map.
 */
@ParametersAreNonnullByDefault
public interface AuthorizationMapManager {
  /**
   * @param useFastAuthz If true, gets the current "fast" map; otherwise gets
   *     the normal map.
   * @return The current authorization map.
   * @throws IOException if there are I/O errors while getting the map.
   */
  @Nonnull
  public AuthorizationMap getAuthorizationMap(boolean useFastAuthz)
      throws IOException;
}
