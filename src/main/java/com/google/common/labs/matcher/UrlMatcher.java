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

/**
 * An implementation of {@link PatternMatcher} for which the pattern language is Google
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
 */
public class UrlMatcher extends PatternMatcherFromMapping {

  public UrlMatcher() {
    super(new UrlMapping<Boolean>());
  }

  /**
   * Accepts a boolean flag which is used to turn on/off the
   * caching mechanism of the pattern matcher. If caching is desired,
   * then it should be true. By default caching is on.
   * @param isCachingEnabled Flag to turn on / off caching mechanism
   *     of pattern matching logic
   */
  public UrlMatcher(boolean isCachingEnabled) {
    super(new UrlMapping<Boolean>(isCachingEnabled));
  }
}
