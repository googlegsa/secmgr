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
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class provides a skeletal implementation of the {@link PatternMatcher}
 * interface, to minimize the effort required to implement this interface.
 * <p>
 * This implementation implements the {@link PatternMatcher#add(String)} and
 * {@link PatternMatcher#addAll(Collection)} methods by delegation to a set. By
 * default, a {@link LinkedHashSet} is used. The implementor may supply a
 * different implementation by using the {@link #AbstractPatternMatcher(Set)}
 * constructor.
 * <p>
 * An implementor may complete the implementation by providing an implementation
 * of {@link PatternMatcher#getMatchList(String)}. The default implementation
 * of {@code matches(String)} and {@code getBestMatch(String)} will use this
 * implementation, but of course, they will be no more efficient. For
 * efficiency, an implementor may also choose to override those methods.
 */
public abstract class AbstractPatternMatcher implements PatternMatcher {

  protected final Set<String> patterns;

  /**
   * Default constructor. Uses a {@link LinkedHashSet} to store the patterns.
   */
  protected AbstractPatternMatcher() {
    this(new LinkedHashSet<String>(), new AtomicInteger(0));
  }

  /**
   * Construct an instance using a supplied backing set for the patterns.
   */
  protected AbstractPatternMatcher(Set<String> patterns) {
    this(patterns, new AtomicInteger(0));
  }

  /**
   * Construct an instance using a supplied AtomicInteger for comparison
   * counting.
   */
  protected AbstractPatternMatcher(AtomicInteger i) {
    this(new LinkedHashSet<String>(), i);
  }

  /**
   * Construct an instance using a supplied backing set for the patterns and a
   * supplied AtomicInteger for comparison counting.
   */
  protected AbstractPatternMatcher(Set<String> patterns, AtomicInteger i) {
    this.patterns = patterns;
    this.comparisonCounter = i;
  }

  @Override
  public boolean add(String e) {
    return patterns.add(Preconditions.checkNotNull(e));
  }

  @Override
  public boolean addAll(Collection<String> c) {
    boolean modified = false;
    for (String pattern : c) {
      modified |= add(pattern);
    }
    return modified;
  }

  @Override
  public boolean remove(String pattern) {
    return patterns.remove(Preconditions.checkNotNull(pattern));
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

  /**
   * Increments the value of the comparison counter. Optionally used for
   * performance testing.
   *
   * @param i the amount to add to the comparison counter.
   */
  protected void incrementComparisonCounter(int i) {
    comparisonCounter.addAndGet(i);
  }

  /**
   * Gets the comparison counter.
   *
   * @return the comparison counter.
   */
  protected AtomicInteger getComparisonCounter() {
    return comparisonCounter;
  }

  @Override
  public boolean matches(String subject) {
    return (getBestMatch(subject) != null);
  }

  @Override
  public String getBestMatch(String subject) {
    List<String> resultList = getMatchList(subject);
    if (resultList == null) {
      return null;
    }
    if (resultList.isEmpty()) {
      return null;
    }
    return resultList.get(0);
  }
}
