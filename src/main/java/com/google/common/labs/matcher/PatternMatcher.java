// Copyright 2008 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.common.labs.matcher;

import com.google.common.collect.ImmutableList;

import java.util.Collection;
import java.util.Set;

/**
 * A PatternMatcher matches subject strings against a set of patterns. For an
 * input subject string, it can produce a list of all the patterns that match
 * that string in "best match" order: {@link #getMatchList(String)}, or the
 * single "best" match: {@link #getBestMatch(String)}, or a boolean to indicate
 * if any pattern matches: {@link #matches(String)}.
 * <p>
 * The caller supplies string patterns using setters similar to the
 * corresponding functions of {@link Set}: {@link #add(String)} and
 * {@link #addAll(Collection)}.
 * <p>
 * The pattern language and the definition of "best" match depends on the
 * implementation.
 */
public interface PatternMatcher {
  /**
   * Add a single pattern string.
   *
   * @param pattern the new pattern
   * @return {@code false} if the pattern is already present; otherwise
   *         {@code true}
   */
  boolean add(String pattern);

  /**
   * Add a collection of pattern strings.
   *
   * @param c a collection of pattern strings
   * @return {@code true} if the pattern set changed as a result of the call
   */
  boolean addAll(Collection<String> c);

  /**
   * Removes the specified pattern from this set if it is present.
   *
   * @param pattern pattern to be removed from this set, if present
   * @return true if the PatternMatcher contained the specified pattern
   */
  boolean remove(String pattern);

  /**
   * Attempts to match the subject string to all the patterns. Returns all
   * matching patterns, with the best match first. Note that the pattern
   * language and "best match" order depend on the implementation.
   *
   * @param subject The string to match
   * @return an immutable list of all patterns that match the subject, with the
   *         best match first, or an empty list if no patterns match
   */
  ImmutableList<String> getMatchList(String subject);

  /**
   * Finds the best pattern that matches the subject string. This method is
   * equivalent to calling {@link #getMatchList(String)} and returning
   * {@code null} if the list {@code isEmpty()}, and the first element of the
   * list if not; however, this method may be faster, depending on the
   * implementation.
   *
   * @param subject The string to match
   * @return The best pattern that matches the subject string or {@code null} if
   *         no patterns match
   */
  String getBestMatch(String subject);

  /**
   * Tests whether any pattern matches the subject string. This method is
   * equivalent to calling {@link #getBestMatch(String)} and returning
   * {@code true} if and only if the result is not {@code null}; however, this
   * method may be faster, depending on the implementation.
   *
   * @param subject The string to match
   * @return {@code true} if and only if at least one pattern matches the
   *         subject
   */
  boolean matches(String subject);

}
