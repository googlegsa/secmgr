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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.common.Resource;

import java.util.List;

import javax.annotation.concurrent.Immutable;

/**
 * A dumb data object containing an authorization method and a set of resources
 * to authorize.
 */
@Immutable
public final class AuthzBatch {
  private final AuthorizationMethod method;
  private final ImmutableList<Resource> resources;

  private AuthzBatch(AuthorizationMethod method, ImmutableList<Resource> resources) {
    this.method = method;
    this.resources = resources;
  }

  public static AuthzBatch make(AuthorizationMethod method, Iterable<Resource> resources) {
    Preconditions.checkNotNull(method);
    Preconditions.checkNotNull(resources);
    return new AuthzBatch(method, ImmutableList.copyOf(resources));
  }

  public AuthorizationMethod getMethod() {
    return method;
  }

  public List<Resource> getResources() {
    return resources;
  }
}
