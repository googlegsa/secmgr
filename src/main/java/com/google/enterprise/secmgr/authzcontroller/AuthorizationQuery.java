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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.common.Resource;

import java.util.List;
import java.util.Objects;

import javax.annotation.concurrent.Immutable;

/**
 * A value class that contains a resource and a queue of methods to be tried for
 * this resource.
 */
@Immutable
public class AuthorizationQuery implements Comparable<AuthorizationQuery> {
  private static final ImmutableList<? extends AuthorizationMethod> NO_METHODS = ImmutableList.of();

  private final Resource resource;
  private final ImmutableList<? extends AuthorizationMethod> methods;

  private AuthorizationQuery(Resource resource,
      ImmutableList<? extends AuthorizationMethod> methods) {
    this.resource = resource;
    this.methods = methods;
  }

  /**
   * Make an authorization query.
   *
   * @param resource The resource being authorized.
   * @param methods The authorization methods to try.
   * @return An authorization query with INDETERMINATE status.
   */
  public static AuthorizationQuery make(Resource resource,
      Iterable<? extends AuthorizationMethod> methods) {
    Preconditions.checkArgument(!Strings.isNullOrEmpty(resource.getUrl()));
    return new AuthorizationQuery(resource, ImmutableList.copyOf(methods));
  }

  @VisibleForTesting
  static AuthorizationQuery make(Resource resource) {
    return make(resource, NO_METHODS);
  }

  public Resource getResource() {
    return resource;
  }

  List<? extends AuthorizationMethod> getMethods() {
    return methods;
  }

  AuthorizationQuery popMethods() {
    Preconditions.checkState(methods.size() > 0);
    return new AuthorizationQuery(resource, methods.subList(1, methods.size()));
  }

  /*
   * This implementation is for testing convenience only. It treats
   * AuthorizationMethod equality superficially: it does not call
   * AuthorizationMethod.equals() - instead, it just compares the getName()
   * strings. This is useful for testing, because we can construct mocks and
   * dummies that pass equality.
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) { return true; }
    if (!(obj instanceof AuthorizationQuery)) { return false; }
    AuthorizationQuery other = (AuthorizationQuery) obj;
    return Objects.equals(resource, other.resource)
        && Objects.equals(methods, other.methods);
  }

  @Override
  public int hashCode() {
    return Objects.hash(resource, methods);
  }

  @Override
  public int compareTo(AuthorizationQuery that) {
    if (this == that) { return 0; }
    return resource.getUrl().compareTo(that.getResource().getUrl());
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append("{resource:\"");
    builder.append(resource);
    builder.append("\", methods:");
    builder.append(methods.toString());
    builder.append("}");
    return builder.toString();
  }
}
