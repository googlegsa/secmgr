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
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * An implementation of {@link PatternMatcher} for which the pattern language is
 * prefix patterns. A prefix pattern {@code p} is a string (no escapes or
 * special characters of any kind) that matches a subject string {@code s} if
 * and only if {@code s.startsWith(p)} is true. The best match (first match
 * returned) is the longest prefix pattern that matches.
 * <p>
 * This implementation simply applies each pattern sequentially, then sorts
 * the matches by length to find the best.
 */
public class SequentialPrefixPatternMatcher extends AbstractPatternMatcher {

  @Override
  public ImmutableList<String> getMatchList(String subject) {
    return ImmutableList.copyOf(getHelper(subject));
  }

  public SequentialPrefixPatternMatcher() {
    this(new AtomicInteger(0));
  }

  public SequentialPrefixPatternMatcher(AtomicInteger i) {
    this(new HashSet<String>(), i);
  }

  public SequentialPrefixPatternMatcher(Set<String> s, AtomicInteger i) {
    super(s, i);
  }

  public SequentialPrefixPatternMatcher(Set<String> s) {
    this(s, new AtomicInteger(0));
  }

  private Set<String> getHelper(String subject) {
    Set<String> result =
        new TreeSet<String>(BinarySearchPrefixPatternMatcher.LENGTH_BASED_COMPARATOR_DESC);
    for (String p: patterns) {
      if (subject.startsWith(p)) {
        result.add(p);
      }
    }
    return result;
  }
}
