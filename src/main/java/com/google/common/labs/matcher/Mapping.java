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

import com.google.common.collect.ImmutableMap;

import java.util.Map;

/**
 * A {@code Mapping} maps subject strings to values according to a set of
 * patterns. Null values are not allowed.
 * <p>
 * For an input subject string, it can produce a map of all the patterns that
 * match that string, with their associated values, in "best match" order:
 * {@link #getMappings(String)}, or the map entry for the single "best" match:
 * {@link #getBestEntry(String)}, or the value associated with the best
 * matching pattern: {@link #getBestValue(String)}.
 * <p>
 * The caller supplies string patterns using setters similar to the
 * corresponding functions of {@link Map}: {@link #put(String, Object)} and
 * {@link #putAll(Map)}.
 * <p>
 * The {@link #getByPattern(String)} method is also provided to fetch a value by
 * the pattern that was supplied in the most recent corresponding {@code put} or
 * {@code putAll} call. This can also be used to test if a mapping exists for a
 * specific pattern.
 * <p>
 * The pattern language and the definition of "best" match depends on the
 * implementation.
 *
 * @param <V> the type of mapped values
 */
public interface Mapping<V> {

  /**
   * Associates the specified value with the specified pattern. If the pattern
   * map previously contained a mapping for the pattern, the old value is
   * replaced by the specified value.
   *
   * @param pattern pattern with which the specified value is to be associated
   * @param value value to be associated with the specified pattern
   * @return the previous value associated with the pattern, or {@code null} if
   *         there was no mapping for the pattern.
   */
  V put(String pattern, V value);

  /**
   * Copies all of the mappings from the specified map to this {@code Mapping}.
   * The effect of this call is equivalent to that of calling
   * {@code put(pattern, v)} on this {@code Mapping} once for each mapping from
   * {@code pattern} to value {@code v} in the specified map.
   *
   * @param m mappings to be stored in this {@code Mapping}
   */
  void putAll(Map<String, ? extends V> m);

  /**
   * Removes the mapping for this pattern from this map if it is present. The
   * return value is the previous value associated with the pattern, or
   * {@code null} if there was no mapping for the pattern.
   *
   * @param pattern pattern whose mapping is to be removed from the map
   * @return the previous value associated with the pattern, or {@code null} if
   *         there was no mapping for the pattern.
   */
  V remove(String pattern);

  /**
   * Finds all patterns that match the subject string with all their associated
   * values. The result is returned as a map, whose iteration order is from best
   * match to worst.
   *
   * @param subject The string to match
   * @return A map giving all matching patterns and their associated values; an
   *         empty map is returned if this {@code Mapping} contains no matching
   *         pattern
   */
  ImmutableMap<String, V> getMappings(String subject);

  /**
   * Finds the best pattern that matches the subject string and its associated
   * value. The result is returned as a map entry.
   *
   * @param subject The string to match
   * @return A map entry with the best matching pattern and its associated
   *         value; {@code null} is returned if this {@code Mapping} contains no
   *         matching pattern
   */
  Map.Entry<String, V> getBestEntry(String subject);

  /**
   * Finds the value associated with the best pattern that matches the subject
   * string.
   *
   * @param subject The string to match
   * @return the value associated with the best matching pattern, or
   *         {@code null} if this {@code Mapping} contains no matching pattern
   */
  V getBestValue(String subject);

  /**
   * Returns the value to which the specified pattern is mapped, or {@code null}
   * if this map contains no mapping for the pattern. The parameter is a
   * pattern, not a subject string to be matched against patterns, so at most
   * one value can be returned. This method can also be used to test whether a
   * mapping exists for a given pattern.
   *
   * @param pattern the pattern whose associated value is to be returned
   * @return the value to which the specified pattern is mapped, or {@code null}
   *         if this map contains no mapping for the pattern
   */
  V getByPattern(String pattern);

  /**
   * Returns the number of mappings.
   *
   * @return the number of mappings.
   */
  int size();

}
