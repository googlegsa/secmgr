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
import com.google.common.collect.Maps;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

/**
 * An implementation of {@link Mapping} for which the pattern language is Google
 * URL patterns; see
 * documentation in <a
 * href="http://code.google.com/apis/searchappliance/documentation/50/admin/URL_patterns.html">
 * this document</a>. Note these limitations:
 * <ul>
 * <li> {@code www?:} patterns are not supported </li>
 * <li> {@code regexp:}, {@code regexpCase:} and {@code regexpIgnoreCase:}
 * patterns are treated as Java regexes, not as GNU regexes (as documented on the
 * <a
 * href="http://code.google.com/apis/searchappliance/documentation/50/admin/URL_patterns.html">
 * reference site</a>). </li>
 * <li> Exception patterns (patterns with leading {@code -} or {@code +-}) are
 * not supported.</li>
 * </ul>
 * <p>
 * The best match order is defined as follows:
 * <ul>
 * <li> The best domain match is determined by the order in which the patterns
 * are added. The first pattern whose domain matches a subject path determines
 * the best domain match. </li>
 * <li> Within the set of all patterns that start with the best domain match,
 * the path exact match is preferred, if there is one, followed by prefix
 * matches from longest to shortest, followed by other matches in the order in
 * which they were added</li>
 * <li> Finally, all free matches ({@code contains}, {@code regexp:},
 * {@code regexpCase:} and {@code regexpIgnoreCase:}, in the order in which
 * they were added.</li>
 * </ul>
 *
 * @param <V> the type of mapped values
 */
public class UrlMapping<V> implements Mapping<V> {

  public interface CollectionFactory<V> {
    /*
     * The domain map is a singleton (per mapping).  It maps each attested domain
     * to a PathMapper that will do the mapping of the paths for that domain.
     */
    Mapping<PathMapper<V>> makeDomainMap(String name);

    /*
     * The full-url mapper is a singleton (per mapping).  It takes care of all
     * the non-host-path type patterns - the ones that have to be mapped against
     * a single url.
     */
    Mapping<Entry<String, V>> makeFullUrlMapper(String name);

    /*
     * Each PathMapper creates an exact-matches map to hold the exact match patterns
     * for that domain.
     */
    Map<String, Entry<String, V>> makeExactMatchesMap(String name);

    /*
     * Each PathMapper creates a prefix mapper to hold the prefix-type patterns
     * for that domain.
     */
    Mapping<Entry<String, V>> makePrefixMapper(String name);

    /*
     * Each PathMapper creates a regex mapper to hold the regex patterns
     * for that domain.
     */
    Mapping<Entry<String, V>> makeRegexMapper(String name);
  }

  private final CollectionFactory<V> collectionFactory;

  /**
   * For host-path patterns (patterns that can be broken into two parts, one for
   * the host part and one for the path part -- see
   * {@link ParsedUrlPattern#isHostPathType()}) we use a hierarchical
   * structure: the {@code domainMap} handles the host portion, and returns a
   * {@link PathMapper} that handles the path portion.
   */
  private final Mapping<PathMapper<V>> domainMap;

  /**
   * For other patterns (typically regexes that could match either host or path)
   * we use a single structure that tries them all sequentially. Obviously,
   * performance is best if these are not used at all.
   */
  private final Mapping<Entry<String, V>> fullUrlMapper;

  private final AtomicInteger comparisonCounter;

  private final AtomicInteger mappingCounter;

  private static final String DEFAULT_NAME = "um";

  private final String name;

  public UrlMapping() {
    this(new AtomicInteger(0));
  }

  public UrlMapping(CollectionFactory<V> collectionFactory) {
    this(new AtomicInteger(0), DEFAULT_NAME, collectionFactory, true);
  }

  public UrlMapping(AtomicInteger i) {
    this(i, DEFAULT_NAME);
  }

  /**
   * This constructor accepts the boolean flag to turn on/off the
   * caching mechanism of the pattern matcher.
   * @param isCachingEnabled set to true if caching is desired; otherwise false
   */
  public UrlMapping(boolean isCachingEnabled) {
    this(new AtomicInteger(0), DEFAULT_NAME, null, isCachingEnabled);
  }

  public UrlMapping(AtomicInteger i, String name) {
    this(i, name, null, true);
  }

  public UrlMapping(AtomicInteger i, String name,
      CollectionFactory<V> collectionFactory) {
    this(i, name, collectionFactory, true);
  }

  public UrlMapping(AtomicInteger i, String name,
       CollectionFactory<V> collectionFactory, boolean isCachingEnabled) {
    comparisonCounter = i;
    this.collectionFactory = (collectionFactory == null) ?
        new DefaultCollectionFactory<V>(isCachingEnabled) : collectionFactory;
    // make the domainMap - maps a url's domain to a special matcher for that domain
    domainMap = this.collectionFactory.makeDomainMap(name);
    // make the fullUrlMapper - which is used when the pattern can't be separated into
    // domain and path patterns
    fullUrlMapper = this.collectionFactory.makeFullUrlMapper(name);
    mappingCounter = new AtomicInteger(0);
    this.name = name;
  }

  @Override
  public Entry<String, V> getBestEntry(String subject) {
    AnalyzedUrl url = new AnalyzedUrl(subject);
    Entry<String, V> result = null;
    for (PathMapper<V> m : domainMap.getMappings(url.getHostPart()).values()) {
      result = m.getBestEntry(url.getPathPart());
      if (result != null) {
        return result;
      }
    }
    Entry<String, Entry<String, V>> fullUrlMatch = fullUrlMapper.getBestEntry(subject);
    if (fullUrlMatch != null) {
      result = fullUrlMatch.getValue();
    }
    return result;
  }

  @Override
  public V getBestValue(String subject) {
    Entry<String, V> e = getBestEntry(subject);
    if (e != null) {
      return e.getValue();
    }
    return null;
  }

  @Override
  public V getByPattern(String pattern) {
    ParsedUrlPattern p = new ParsedUrlPattern(pattern);
    if (p.isHostPathType()) {
      String hostRegex = p.getHostRegex();
      PathMapper<V> m = domainMap.getByPattern(hostRegex);
      if (m == null) {
        return null;
      }
      return m.getByPattern(p);
    } else {
      Entry<String, V> v = fullUrlMapper.getByPattern(p.getUrlRegex());
      if (v == null) {
        return null;
      }
      return v.getValue();
    }
  }

  @Override
  public ImmutableMap<String, V> getMappings(String subject) {
    AnalyzedUrl url = new AnalyzedUrl(subject);
    Map<String, V> result = new LinkedHashMap<String, V>();
    for (PathMapper<V> m : domainMap.getMappings(url.getHostPart()).values()) {
      result.putAll(m.getMappings(url.getPathPart()));
    }
    for (Entry<String, V> v : fullUrlMapper.getMappings(subject).values()) {
      result.put(v.getKey(), v.getValue());
    }
    return ImmutableMap.copyOf(result);
  }

  /** @throws IllegalArgumentException if the pattern is unsupported */
  @Override
  public V put(String pattern, V value) {
    ParsedUrlPattern p = new ParsedUrlPattern(pattern);
    if (p.isHostPathType()) {
      String hostRegex = p.getHostRegex();
      PathMapper<V> m = getPathMapper(hostRegex);
      m.addParsedUrl(p, value);
    } else {
      String urlRegex = p.getUrlRegex();
      Entry<String, V> v = Maps.immutableEntry(pattern, value);
      fullUrlMapper.put(urlRegex, v);
    }
    mappingCounter.incrementAndGet();
    return value;
  }

  private PathMapper<V> getPathMapper(String hostRegex) {
    PathMapper<V> m = domainMap.getByPattern(hostRegex);
    if (m == null) {
      m = new PathMapper<V>(name + hostRegex, collectionFactory);
      domainMap.put(hostRegex, m);
    }
    return m;
  }

  /** @throws IllegalArgumentException if any pattern is unsupported */
  @Override
  public void putAll(Map<String, ? extends V> m) {
    for (Map.Entry<String, ? extends V> e : m.entrySet()) {
      put(e.getKey(), e.getValue());
    }
  }

  @Override
  public V remove(String pattern) {
    ParsedUrlPattern p = new ParsedUrlPattern(pattern);
    V value;
    if (p.isHostPathType()) {
      String hostRegex = p.getHostRegex();
      PathMapper<V> m = getPathMapper(hostRegex);
      value = m.removeParsedUrl(p);
    } else {
      String urlRegex = p.getUrlRegex();
      value = fullUrlMapper.remove(urlRegex).getValue();
    }
    mappingCounter.decrementAndGet();
    return value;
  }

  /**
   * Set a counter to count basic operations. Optionally used for performance
   * testing.
   *
   * @param count the value to set the comparison counter.
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
   * Increment the value of the comparison counter. Optionally used for
   * performance testing.
   *
   * @param i the amount to add to the comparison counter.
   */
  protected void incrementComparisonCounter(int i) {
    comparisonCounter.addAndGet(i);
  }

  /**
   * Returns the number of mappings.
   *
   * @return the number of mappings.
   */
  @Override
  public int size() {
    return mappingCounter.intValue();
  }

  public static class PathMapper<V> {

    private final Map<String, Entry<String, V>> exactMatches;
    private final Mapping<Entry<String, V>> prefixMapper;
    private final Mapping<Entry<String, V>> regexMapper;
    private final String name;

    public PathMapper(String name, CollectionFactory<V> collectionFactory) {
      this.name = name;
      exactMatches = collectionFactory.makeExactMatchesMap(name);
      prefixMapper = collectionFactory.makePrefixMapper(name);
      regexMapper = collectionFactory.makeRegexMapper(name);
    }

    public V removeParsedUrl(ParsedUrlPattern p) {
      V value = null;
      if (p.isPathExactMatch()) {
        value = exactMatches.remove(p.getPathExactString()).getValue();
      } else if (p.isPathPrefixMatch()) {
        value = prefixMapper.remove(p.getPathPrefixString()).getValue();
      } else if (p.isHostPathType()) {
        value = regexMapper.remove(p.getPathRegex()).getValue();
      }
      return value;
    }

    public V getByPattern(ParsedUrlPattern p) {
      Entry<String, V> pmv;
      if (p.isPathExactMatch()) {
        pmv = exactMatches.get(p.getPathExactString());
      } else if (p.isPathPrefixMatch()) {
        pmv = prefixMapper.getByPattern(p.getPathPrefixString());
      } else /* we know p.isHostPathType() */ {
        pmv = regexMapper.getByPattern(p.getPathRegex());
      }
      V result = null;
      if (pmv != null) {
        result = pmv.getValue();
      }
      return result;
    }

    public void addParsedUrl(ParsedUrlPattern p, V value) {
      String urlPattern = p.getUrlPattern();
      Entry<String, V> pmv = Maps.immutableEntry(urlPattern, value);
      if (p.isPathExactMatch()) {
        exactMatches.put(p.getPathExactString(), pmv);
      } else if (p.isPathPrefixMatch()) {
        prefixMapper.put(p.getPathPrefixString(), pmv);
      } else if (p.isHostPathType()) {
        regexMapper.put(p.getPathRegex(), pmv);
      } else {
        throw new IllegalArgumentException();
      }
    }

    public Entry<String, V> getBestEntry(String subject) {
      Entry<String, V> pmv = null;
      pmv = exactMatches.get(subject);
      if (pmv == null) {
        pmv = prefixMapper.getBestValue(subject);
      }
      if (pmv == null) {
        pmv = regexMapper.getBestValue(subject);
      }
      return pmv;
    }

    public Map<String, V> getMappings(String subject) {
      Map<String, V> result = new LinkedHashMap<String, V>();
      Entry<String, V> pmv = null;
      pmv = exactMatches.get(subject);
      if (pmv != null) {
        result.put(pmv.getKey(), pmv.getValue());
      }
      for (Entry<String, V> p : prefixMapper.getMappings(subject).values()) {
        result.put(p.getKey(), p.getValue());
      }
      for (Entry<String, V> p : regexMapper.getMappings(subject).values()) {
        result.put(p.getKey(), p.getValue());
      }
      return result;
    }

    public String getName() {
      return name;
    }
  }

  private class DefaultCollectionFactory<V> implements CollectionFactory<V> {
    private final boolean useCache;

    private DefaultCollectionFactory(boolean useCache) {
      this.useCache = useCache;
    }

    @Override
    public Mapping<PathMapper<V>> makeDomainMap(String name) {
      Map<String, Pattern> dpm = new HashMap<String, Pattern>();
      PatternMatcher patternMatcher =
          new SequentialRegexPatternMatcher(UrlMapping.this.comparisonCounter, dpm);
      if (useCache) {
         patternMatcher = new CachedPatternMatcher(patternMatcher,
             UrlMapping.this.comparisonCounter);
      }
      Mapping<PathMapper<V>> domainMap
          = new MappingFromPatternMatcher<PathMapper<V>>(patternMatcher);
      return domainMap;
    }

    @Override
    public Mapping<Entry<String, V>> makeFullUrlMapper(String name) {
      Map<String, Pattern> fpm = new HashMap<String, Pattern>();
      SequentialRegexPatternMatcher fm =
          new SequentialRegexPatternMatcher(UrlMapping.this.comparisonCounter, fpm);
      Mapping<Entry<String, V>> fullUrlMapper = new MappingFromPatternMatcher<Entry<String, V>>(fm);
      return fullUrlMapper;
    }

    @Override
    public Map<String, Entry<String, V>> makeExactMatchesMap(String name) {
      return new HashMap<String, Entry<String, V>>();
    }

    @Override
    public Mapping<Entry<String, V>> makePrefixMapper(String name) {
      return new MappingFromPatternMatcher<Entry<String, V>>(new TriePrefixPatternMatcher());
    }

    @Override
    public Mapping<Entry<String, V>> makeRegexMapper(String name) {
      return new MappingFromPatternMatcher<Entry<String, V>>(new SequentialRegexPatternMatcher());
    }

  }
}
