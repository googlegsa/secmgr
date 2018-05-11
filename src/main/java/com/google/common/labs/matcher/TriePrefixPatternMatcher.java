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
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * An implementation of {@link PatternMatcher} for which the pattern language is
 * prefix patterns. A prefix pattern {@code p} is a string (no escapes or
 * special characters of any kind) that matches a subject string {@code s} if
 * and only if {@code s.startsWith(p)} is true. The best match (first match
 * returned) is the longest prefix pattern that matches.
 * <p>
 * This implementation of uses a component-wise trie; that is, instead of a node
 * for each character, the string is broken into components at a delimiter
 * (default is "/"), and there is node for each component. This makes sense for
 * file-system paths and similarly structured strings.
 */
public class TriePrefixPatternMatcher extends AbstractPatternMatcher {
  private TrieNode root;
  private String componentDelimiter;
  private int componentDelimiterLength;

  public TriePrefixPatternMatcher() {
    this("/", new AtomicInteger(0));
  }

  public TriePrefixPatternMatcher(String componentDelimiter) {
    this(componentDelimiter, new AtomicInteger(0));
  }

  public TriePrefixPatternMatcher(AtomicInteger i) {
    this("/", i);
  }

  public TriePrefixPatternMatcher(String componentDelimiter, AtomicInteger i) {
    super(new HashSet<String>(), i);
    Preconditions.checkNotNull(componentDelimiter);
    Preconditions.checkArgument(componentDelimiter.length() > 0,
        "component delimiter may not be empty string");
    root = new TrieNode();
    this.componentDelimiter = componentDelimiter;
    this.componentDelimiterLength = componentDelimiter.length();
  }

  @Override
  public boolean add(String pattern) {
    if (!super.add(pattern)) {
      return false;
    }
    root.add(pattern);
    return true;
  }

  @Override
  public boolean remove(String pattern) {
    super.remove(pattern);
    return root.remove(pattern);
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

  /* @Override */
  @Override
  public ImmutableList<String> getMatchList(String subject) {
    return ImmutableList.copyOf(getHelper(subject, false));
  }

  private List<String> getHelper(String subject, Boolean getFirstOnly) {
    return root.getHelper(subject, getFirstOnly, "");
  }

  private class TrieNode {
    Map<String, TrieNode> componentMatches = new HashMap<String, TrieNode>();
    PatternMatcher stringMatches = new BinarySearchPrefixPatternMatcher(getComparisonCounter());

    public void add(String patternString) {
      int i = patternString.indexOf(componentDelimiter);
      if (i < 0) {
        stringMatches.add(patternString);
        return;
      }
      String component = patternString.substring(0, i);
      TrieNode nextMap = componentMatches.get(component);
      if (nextMap == null) {
        nextMap = new TrieNode();
        componentMatches.put(component, nextMap);
      }
      String next = patternString.substring(i + componentDelimiterLength);
      nextMap.add(next);
    }

    public boolean remove(String patternString) {
      int i = patternString.indexOf(componentDelimiter);
      if (i < 0) {
        return stringMatches.remove(patternString);
      }
      String component = patternString.substring(0, i);
      TrieNode nextMap = componentMatches.get(component);
      if (nextMap == null) {
        return false;
      }
      String next = patternString.substring(i + componentDelimiterLength);
      return nextMap.remove(next);
    }

    private List<String> getHelper(String subject, boolean getFirstOnly, String prefix) {
      List<String> result = new ArrayList<String>();
      int comparisons = 0;
      int i = subject.indexOf(componentDelimiter);
      if (i >= 0) {
        String component = subject.substring(0, i);
        TrieNode nextMap = componentMatches.get(component);
        comparisons++;
        if (nextMap != null) {
          String nextPrefix = prefix + component + componentDelimiter;
          String nextS = subject.substring(i + componentDelimiterLength);
          result.addAll(nextMap.getHelper(nextS, getFirstOnly, nextPrefix));
          if (result.size() > 0 && getFirstOnly) {
            incrementComparisonCounter(comparisons);
            return result;
          }
        }
        subject = component;
      }
      if (getFirstOnly) {
        String e = stringMatches.getBestMatch(subject);
        if (e != null) {
          result.add(prefix + e);
        }
      } else {
        for (String e : stringMatches.getMatchList(subject)) {
          result.add(prefix + e);
        }
      }
      incrementComparisonCounter(comparisons);
      return result;
    }
  }
}
