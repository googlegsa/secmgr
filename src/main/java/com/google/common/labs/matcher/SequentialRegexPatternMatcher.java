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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An implementation of {@link PatternMatcher} for which the pattern language is
 * java regexes. The insertion-order of the patterns determines the order in
 * which matches are returned. See {@link LinkedHashMap} for definition of
 * insertion order.
 * <p>
 * This implementation simply applies each pattern sequentially, in insertion
 * order. Note: this implementation is not thread safe.
 */
public class SequentialRegexPatternMatcher extends AbstractPatternMatcher {

  private final Map<String, Pattern> patternMap;

  @Override
  public boolean add(String e) {
    if (!super.add(e)) {
      return false;
    }
    Pattern pattern = Pattern.compile(e);
    patternMap.put(e, pattern);
    return true;
  }

  @Override
  public String getBestMatch(String subject) {
    List<String> resultList = getHelper(subject, true);
    if (resultList == null) {
      return null;
    }
    if (resultList.isEmpty()) {
      return null;
    }
    return resultList.get(0);
  }

  @Override
  public ImmutableList<String> getMatchList(String subject) {
    return ImmutableList.copyOf(getHelper(subject, false));
  }

  public SequentialRegexPatternMatcher() {
    this(new AtomicInteger(0));
  }

  public SequentialRegexPatternMatcher(AtomicInteger i) {
    this(i, new HashMap<String, Pattern>());
  }

  public SequentialRegexPatternMatcher(AtomicInteger i, Map<String, Pattern> patternMap) {
    super(i);
    this.patternMap = patternMap;
  }

  public SequentialRegexPatternMatcher(AtomicInteger i, Map<String, Pattern> patternMap,
      Set<String> patterns) {
    super(patterns, i);
    this.patternMap = patternMap;
  }

  private List<String> getHelper(String s, boolean getFirstOnly) {
    List<String> result = new ArrayList<String>();
    int comparisons = 0;
    for (String patternString : patterns) {
      Pattern pattern = patternMap.get(patternString);
      Matcher matcher = pattern.matcher(s);
      comparisons++;
      if (matcher.find()) {
        result.add(patternString);
        if (getFirstOnly) {
          break;
        }
      }
    }
    incrementComparisonCounter(comparisons);
    return result;
  }
}
