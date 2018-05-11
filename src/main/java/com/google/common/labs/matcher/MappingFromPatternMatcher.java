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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;

import java.util.HashMap;
import java.util.Map;

/**
 * A {@link Mapping} implementation that's built from a {@link PatternMatcher}.
 *
 * @param <V> the type of mapped values
 */
public class MappingFromPatternMatcher<V> implements Mapping<V> {
  private final PatternMatcher patternMatcher;
  private final Map<String, V> patternMap;
  private int mappingCounter;

  /**
   * Construct a {@code MappingFromPatternMatcher} by supplying a fully
   * constructed {@link PatternMatcher}.
   *
   * @param patternMatcher the pattern matcher that will be used to do the work
   */
  public MappingFromPatternMatcher(PatternMatcher patternMatcher) {
    this(patternMatcher, new HashMap<String, V>());
  }

  /**
   * Construct a {@code MappingFromPatternMatcher} by supplying a fully
   * constructed {@link PatternMatcher} and a {@code Map<String, V>} in which
   * the mappings are stored.
   *
   * @param patternMatcher the pattern matcher that will be used to do the work
   * @param patternMap a {@code Map<String, V>} in which the mappings are stored.
   */
  public MappingFromPatternMatcher(PatternMatcher patternMatcher,
      Map<String, V> patternMap) {
    Preconditions.checkNotNull(patternMatcher);
    this.patternMatcher = patternMatcher;
    this.patternMap = patternMap;
    this.mappingCounter = 0;
  }

  @Override
  public V put(String pattern, V value) {
    Preconditions.checkNotNull(pattern);
    Preconditions.checkNotNull(value);
    patternMatcher.add(pattern);
    mappingCounter++;
    return patternMap.put(pattern, value);
  }

  @Override
  public void putAll(Map<String, ? extends V> m) {
    if (m.containsValue(null)) {
      throw new NullPointerException();
    }
    patternMatcher.addAll(m.keySet());
    patternMap.putAll(m);
    mappingCounter += m.size();
  }

  @Override
  public V remove(String pattern) {
    V value = patternMap.remove(Preconditions.checkNotNull(pattern));
    patternMatcher.remove(pattern);
    mappingCounter--;
    return value;
  }

  @Override
  public V getByPattern(String pattern) {
    return patternMap.get(Preconditions.checkNotNull(pattern));
  }

  @Override
  public V getBestValue(String subject) {
    String bestPattern = patternMatcher.getBestMatch(subject);
    if (bestPattern == null) {
      return null;
    }
    return patternMap.get(bestPattern);
  }

  @Override
  public Map.Entry<String, V> getBestEntry(String subject) {
    String bestPattern = patternMatcher.getBestMatch(subject);
    if (bestPattern == null) {
      return null;
    }
    return Maps.immutableEntry(bestPattern, patternMap.get(bestPattern));
  }

  @Override
  public ImmutableMap<String, V> getMappings(String subject) {
    ImmutableMap.Builder<String, V> builder = ImmutableMap.builder();
    for (String match : patternMatcher.getMatchList(subject)) {
      builder.put(match, patternMap.get(match));
    }
    return builder.build();
  }

  @Override
  public int size() {
    return mappingCounter;
  }
}
