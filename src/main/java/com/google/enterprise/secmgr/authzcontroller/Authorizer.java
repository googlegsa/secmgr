/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.enterprise.secmgr.authzcontroller;

import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.modules.AuthzResult;

import java.util.Collection;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;

/**
 * An interface describing an abstract authorizer.
 */
@ParametersAreNonnullByDefault
public interface Authorizer {
  /**
   * Runs this authorizer on some resources.
   *
   * @param resources Some resources to be authorized.
   * @param sessionId A sessionId to use for authorization.
   * @param enableFastAuthz If true, only use "fast" authorization mechanisms.
   * @return The authorization results for the given resources.
   */
  @Nonnull
  public AuthzResult apply(Collection<Resource> resources, String sessionId,
      boolean enableFastAuthz);
}
