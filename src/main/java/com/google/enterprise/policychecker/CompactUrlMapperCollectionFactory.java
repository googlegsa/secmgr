// Copyright 2009 Google Inc.
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

package com.google.enterprise.policychecker;

import com.google.common.labs.matcher.CachedPatternMatcher;
import com.google.common.labs.matcher.Mapping;
import com.google.common.labs.matcher.MappingFromPatternMatcher;
import com.google.common.labs.matcher.SequentialRegexPatternMatcher;
import com.google.common.labs.matcher.TriePrefixPatternMatcher;
import com.google.common.labs.matcher.UrlMapping.CollectionFactory;
import com.google.common.labs.matcher.UrlMapping.PathMapper;

import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * Factory methods for {@code com.google.common.labs.matcher.UrlMapping} that
 * use
 * a {@code MdUrlMap} to save memory.
 */
public class CompactUrlMapperCollectionFactory<V> implements CollectionFactory<V> {

  /* @Override */
  public Map<String, Entry<String, V>> makeExactMatchesMap(String name) {
    // this is the one where we'll really save memory
    // but by using this implementation we can no longer get keys or entries
    // (the keys are one-way hashed, so they can't be reversed)
    return new CompactExactMatchMap<V>();
  }

  /* @Override */
  public Map<String, Pattern> makePatternMap(String name) {
    // this is the same as the DefaultCollectionFactory
    return new ConcurrentHashMap<String, Pattern>();
  }

  /* @Override */
  public Mapping<Entry<String, V>> makePrefixMapper(String name) {
    return new MappingFromPatternMatcher<Entry<String, V>>(
        new TriePrefixPatternMatcher(),
        new ConcurrentHashMap<String, Entry<String, V>>());
  }

  /* @Override */
  public Mapping<Entry<String, V>> makeRegexMapper(String name) {
    return new MappingFromPatternMatcher<Entry<String, V>>(
        new SequentialRegexPatternMatcher(),
        new ConcurrentHashMap<String, Entry<String, V>>());
  }

  /* @Override */
  public Mapping<PathMapper<V>> makeDomainMap(String name) {
    Map<String, Pattern> dpm = new ConcurrentHashMap<String, Pattern>();
    SequentialRegexPatternMatcher dm =
        new SequentialRegexPatternMatcher(new AtomicInteger(), dpm);
    CachedPatternMatcher cm = new CachedPatternMatcher(dm, new AtomicInteger());
    Mapping<PathMapper<V>> domainMap =
      new MappingFromPatternMatcher<PathMapper<V>>(cm,
          new ConcurrentHashMap<String, PathMapper<V>>());
    return domainMap;
  }

  /* @Override */
  public Mapping<Entry<String, V>> makeFullUrlMapper(String name) {
    Map<String, Pattern> fpm = new ConcurrentHashMap<String, Pattern>();
    SequentialRegexPatternMatcher fm =
        new SequentialRegexPatternMatcher(new AtomicInteger(), fpm);
    Mapping<Entry<String, V>> fullUrlMapper =
      new MappingFromPatternMatcher<Entry<String, V>>(fm,
          new ConcurrentHashMap<String, Entry<String, V>>());
    return fullUrlMapper;
  }
}
