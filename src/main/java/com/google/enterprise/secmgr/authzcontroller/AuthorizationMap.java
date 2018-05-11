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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.labs.matcher.ParsedUrlPattern;
import com.google.enterprise.secmgr.common.Resource;

import java.util.List;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * This class is responsible for determining which {@link AuthorizationMethod}s
 * should be run for each resource.  It contains a list of rules that can be
 * applied to a set of resources to compute a set of {@link AuthorizationQuery}
 * objects.
 * <p>
 * The {@link AuthorizationMap.Builder} class is used to construct the list.
 * The order in which the rules are added to the builder determines the
 * preferred matching order.  If a resource matches two or more patterns, then
 * the order in which those rules were added will determine the order in which
 * those methods will be tried.
 */
@Immutable
@ParametersAreNonnullByDefault
public final class AuthorizationMap {

  @Nonnull private final ImmutableList<Rule> rules;

  private AuthorizationMap(ImmutableList<Rule> rules) {
    this.rules = rules;
  }

  /**
   * @return A new authorization map builder.
   */
  @Nonnull
  public static Builder builder() {
    return new Builder();
  }

  /**
   * A builder factory for creating authorization map instances.
   */
  @NotThreadSafe
  @ParametersAreNonnullByDefault
  public static final class Builder {
    private ImmutableList.Builder<Rule> listBuilder;

    private Builder() {
      listBuilder = ImmutableList.builder();
    }

    /**
     * Adds a rule to the map being built.
     *
     * @param pattern The URL pattern for the rule.
     * @param method The authorization method for the rule.
     * @return This builder, for convenience.
     */
    @Nonnull
    public Builder addRule(String pattern, AuthorizationMethod method) {
      Preconditions.checkNotNull(pattern);
      Preconditions.checkNotNull(method);
      ParsedUrlPattern p = new ParsedUrlPattern(pattern);
      String urlRegex = p.getUrlRegex();
      listBuilder.add(new Rule(Pattern.compile(urlRegex), method));
      return this;
    }

    /**
     * @return The authorization map for this builder.
     */
    @Nonnull
    public AuthorizationMap build() {
      return new AuthorizationMap(listBuilder.build());
    }
  }

  /**
   * Maps some resources to authorization query objects.
   *
   * @param resources The resources to be mapped.
   * @return The corresponding authorization query objects.
   */
  @Nonnull
  public List<AuthorizationQuery> mapResources(Iterable<Resource> resources) {
    ImmutableList.Builder<AuthorizationQuery> listBuilder = ImmutableList.builder();
    for (Resource resource : resources) {
      listBuilder.add(mapResource(resource));
    }
    return listBuilder.build();
  }

  @Nonnull
  private AuthorizationQuery mapResource(Resource resource) {
    Preconditions.checkNotNull(resource);
    return AuthorizationQuery.make(resource, getMatchingMethods(resource));
  }

  @Nonnull
  private List<AuthorizationMethod> getMatchingMethods(Resource resource) {
    ImmutableList.Builder<AuthorizationMethod> listBuilder = ImmutableList.builder();
    for (Rule rule : rules) {
      if (rule.getPattern().matcher(resource.getUrl()).find()) {
        listBuilder.add(rule.getMethod());
      }
    }
    return listBuilder.build();
  }

  @Immutable
  @ParametersAreNonnullByDefault
  private static final class Rule {
    @Nonnull private final Pattern pattern;
    @Nonnull private final AuthorizationMethod method;

    Rule(Pattern pattern, AuthorizationMethod method) {
      this.pattern = pattern;
      this.method = method;
    }

    @Nonnull Pattern getPattern() {
      return pattern;
    }

    @Nonnull AuthorizationMethod getMethod() {
      return method;
    }
  }
}
