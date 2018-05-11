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
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * An implementation of {@link PatternMatcher} for which the pattern language is
 * prefix patterns. A prefix pattern {@code p} is a string (no escapes or
 * special characters of any kind) that matches a subject string {@code s} if
 * and only if {@code s.startsWith(p)} is true. The best match (first match
 * returned) is the longest prefix pattern that matches.
 * <p>
 * This implementation uses an ordered collection of patterns, and uses a binary
 * search to get to the best match.
 */
public class BinarySearchPrefixPatternMatcher extends AbstractPatternMatcher {

  /**
   * This comparator sorts by string length first, then in natural order for
   * strings of the same length. Thus, for strings of different lengths, the
   * shorter comes first; for same-length strings, they are in natural order.
   */
  public static final Comparator<String> LENGTH_BASED_COMPARATOR = new Comparator<String>() {
    @Override
    public int compare(String o1, String o2) {
      Preconditions.checkNotNull(o1);
      Preconditions.checkNotNull(o2);
      if (o1.length() == o2.length()) {
        return o1.compareTo(o2);
      } else {
        return o1.length() - o2.length();
      }
    }
  };

  /**
   * Descending order version of the above comparator.
   */
  public static final Comparator<String> LENGTH_BASED_COMPARATOR_DESC = new Comparator<String>() {
    @Override
    public int compare(String o1, String o2) {
      return - LENGTH_BASED_COMPARATOR.compare(o1, o2);
    }
  };

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

  private SortedSet<String> sortedPatterns() {
    return (SortedSet<String>) patterns;
  }

  public BinarySearchPrefixPatternMatcher() {
    super(new TreeSet<String>(LENGTH_BASED_COMPARATOR_DESC));
  }

  public BinarySearchPrefixPatternMatcher(AtomicInteger i) {
    super(new TreeSet<String>(LENGTH_BASED_COMPARATOR_DESC), i);
  }

  private static int log2(int i) {
    if (i <= 0) {
      return 0;
    }
    return (int) Math.ceil(Math.log(i) / Math.log(2.0));
  }

  private List<String> getHelper(String subject, boolean getFirstOnly) {
    List<String> result = new ArrayList<String>();
    SortedSet<String> ps = sortedPatterns();
    if (ps.isEmpty()) {
      return result;
    }
    int comparisons = log2(ps.size());
    ps = ps.tailSet(subject);
    while (!ps.isEmpty()) {
      String pattern = ps.first();
      // invariant: pattern.length() <= subject.length()
      int nextLength = pattern.length();
      comparisons++;
      if (subject.startsWith(pattern)) {
        result.add(pattern);
        if (getFirstOnly) {
          break;
        }
        nextLength--;
      } else if (subject.length() == nextLength) {
        nextLength--;
      }
      if (nextLength < 0) {
        break;
      }
      subject = subject.substring(0, nextLength);
      comparisons += log2(ps.size());
      ps = ps.tailSet(subject);
    }
    incrementComparisonCounter(comparisons);
    return result;
  }
}
