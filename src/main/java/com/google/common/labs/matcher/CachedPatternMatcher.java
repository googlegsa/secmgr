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
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A cached implementation of {@link PatternMatcher}. Supply a
 * separately-constructed {@code PatternMatcher} when constructing this class;
 * the instance will then delegate to that implementation, but keep a cache of
 * its results and will check this cache before calling the internal
 * implementation.
 * <p>
 * At present, there is no control on the size of the cache: it grows without
 * bound.
 * <p>
 * This class is not thread-safe.
 */
public class CachedPatternMatcher implements PatternMatcher {
  private final Map<String, CacheEntry> cache;

  private final PatternMatcher patternMatcher;

  public CachedPatternMatcher(PatternMatcher patternMatcher) {
    this(patternMatcher, new AtomicInteger(0));
  }

  public CachedPatternMatcher(PatternMatcher patternMatcher, AtomicInteger i) {
    this.patternMatcher = Preconditions.checkNotNull(patternMatcher);
    // TODO: allow externally supplied caches
    cache = new HashMap<String, CacheEntry>();
    comparisonCounter = i;
  }

  @Override
  public boolean add(String pattern) {
    return patternMatcher.add(Preconditions.checkNotNull(pattern));
  }

  @Override
  public boolean addAll(Collection<String> c) {
    return patternMatcher.addAll(c);
  }

  @Override
  public boolean remove(String pattern) {
    cache.remove(Preconditions.checkNotNull(pattern));
    return patternMatcher.remove(pattern);
  }

  @Override
  public boolean matches(String subject) {
    return getBestMatch(subject) != null;
  }

  @Override
  public String getBestMatch(String subject) {
    CacheEntry cacheEntry = cache.get(subject);
    comparisonCounter.incrementAndGet();
    if (cacheEntry != null) {
      if (!cacheEntry.matches()) {
        return null;
      }
      return cacheEntry.getBestMatch();
    }
    String result = patternMatcher.getBestMatch(subject);
    if (result == null) {
      cacheEntry = new CacheEntry(false);
      cache.put(subject, cacheEntry);
      return result;
    }
    cacheEntry = new CacheEntry(true);
    cache.put(subject, cacheEntry);
    cacheEntry.setBestMatch(result);
    return result;
  }

  @Override
  public ImmutableList<String> getMatchList(String subject) {
    CacheEntry cacheEntry = cache.get(subject);
    if (cacheEntry != null) {
      if (!cacheEntry.matches()) {
        return ImmutableList.of();
      }
      if (cacheEntry.getMatchList() != null) {
        return cacheEntry.getMatchList();
      }
    }
    ImmutableList<String> result = patternMatcher.getMatchList(subject);
    if (result.isEmpty()) {
      cacheEntry = new CacheEntry(false);
      cache.put(subject, cacheEntry);
      return result;
    }
    if (cacheEntry == null) {
      cacheEntry = new CacheEntry(true);
    }
    cache.put(subject, cacheEntry);
    cacheEntry.setMatches(result);
    return result;
  }

  private final AtomicInteger comparisonCounter;

  /**
   * Set a counter to count basic operations. Optionally used for performance
   * testing.
   *
   * @param count the value to set the comparison counter
   */
  public void setComparisonCounter(int count) {
    // This is a shared counter, so a j.u.c.AtomicInteger is used.
    comparisonCounter.set(count);
  }

  /**
   * Returns the value of the comparison counter. Optionally used for
   * performance testing.
   *
   * @return the value of the comparison counter.
   */
  public int getComparisonCount() {
    return comparisonCounter.intValue();
  }

  private static class CacheEntry {
    private boolean isMatch;
    private String bestMatch;
    private ImmutableList<String> matchList;

    public CacheEntry(boolean matches) {
      this.isMatch = matches;
      bestMatch = null;
      matchList = null;
    }

    boolean matches() {
      return isMatch;
    }

    String getBestMatch() {
      return bestMatch;
    }

    void setBestMatch(String bestMatch) {
      this.bestMatch = bestMatch;
      isMatch = (bestMatch != null);
    }

    ImmutableList<String> getMatchList() {
      return matchList;
    }

    void setMatches(ImmutableList<String> matchList) {
      this.matchList = matchList;
      if (matchList.isEmpty()) {
        setBestMatch(null);
      } else {
        setBestMatch(matchList.get(0));
      }
    }
  }

}
