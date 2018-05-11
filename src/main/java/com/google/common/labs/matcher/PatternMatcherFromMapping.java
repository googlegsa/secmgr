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
import com.google.common.collect.ImmutableList;
import java.util.Collection;
import java.util.Map.Entry;

/**
 * A {@link PatternMatcher} implementation that's built from a {@link Mapping}.
 */
public class PatternMatcherFromMapping implements PatternMatcher {

  private final Mapping<Boolean> patternMapper;

  /**
   * Construct a PatternMatcherFromMapping by supplying a fully constructed
   * {@link Mapping}.
   *
   * @param mapping the mapping that will do the work
   */
  public PatternMatcherFromMapping(Mapping<Boolean> mapping) {
    Preconditions.checkNotNull(mapping);
    this.patternMapper = mapping;
  }

  @Override
  public boolean add(String pattern) {
    Object o = patternMapper.put(Preconditions.checkNotNull(pattern), Boolean.TRUE);
    return o != Boolean.TRUE;
  }

  @Override
  public boolean addAll(Collection<String> c) {
    Preconditions.checkNotNull(c);
    boolean result = false;
    for (String s : c) {
      result = add(s) || result;
    }
    return result;
  }

  @Override
  public boolean remove(String pattern) {
    Boolean b = patternMapper.remove(Preconditions.checkNotNull(pattern));
    return (b != null);
  }

  @Override
  public String getBestMatch(String subject) {
    Entry<String, Boolean> bestEntry = patternMapper.getBestEntry(subject);
    if (bestEntry == null) {
      return null;
    } else {
      return bestEntry.getKey();
    }
  }

  @Override
  public ImmutableList<String> getMatchList(String subject) {
    return ImmutableList.copyOf(patternMapper.getMappings(subject).keySet());
  }

  @Override
  public boolean matches(String subject) {
    return getBestMatch(subject) != null;
  }

}
