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

import static com.google.common.labs.matcher.ParsedUrlPattern.URL_METAPATTERN;
import static com.google.common.labs.matcher.ParsedUrlPattern.getGroup;

import com.google.common.base.Preconditions;
import com.google.common.labs.matcher.ParsedUrlPattern.MetaRegexGroup;

import java.util.regex.Matcher;

/**
 * Analyzer for URL strings, for use with the {@link ParsedUrlPattern}. You can
 * access the host and path portions through {@link AnalyzedUrl#getHostPart()}
 * and {@link AnalyzedUrl#getPathPart()}. It is recommended that this parser be
 * used rather than the standard {@code getHost()} and {@code getPath()}
 * functions of {@link java.net.URL}, because this class and
 * {@code ParsedUrlPattern} share parsing infrastructure and at present, there
 * is at least one significant difference: {@code AnalyzedUrl.getPathPart()}
 * includes the leading slash but {@code java.net.URL.getPath()} does not. TODO:
 * fix this.
 */
class AnalyzedUrl {
  private final String completeUrl;
  private final String host;
  private final String path;

  /**
   * Parses a URL string into components. These components may be empty if the
   * input is fragmentary.
   *
   * @param url the URL string to parse
   */
  public AnalyzedUrl(String url) {
    Preconditions.checkNotNull(url);
    String pathPart = null;
    String hostPart = null;
    // extract the components from the subject string
    Matcher m = URL_METAPATTERN.matcher(url);
    if (m.find()) {
      hostPart = buildHostPart(m);
      pathPart = buildPathPart(m);
    }
    completeUrl = url;
    path = pathPart;
    host = hostPart;
  }

  /**
   * Returns the host (protocol-authority) part: from the beginning up through
   * the first single-slash.
   *
   * @return the host (protocol-authority) portion of the URL, as a String
   */
  public String getHostPart() {
    return host;
  }

  /**
   * Returns the path part from the first single-slash through the end (includes
   * anchor and query if present).
   *
   * @return the path portion of the URL, as a String
   */
  public String getPathPart() {
    return path;
  }

  /**
   * Returns the complete URL.
   *
   * @return the entire URL, as a String
   */
  public String getCompleteUrl() {
    return completeUrl;
  }

  private String buildHostPart(Matcher m) {
    StringBuilder sb = new StringBuilder();
    sb.append(getGroup(m, MetaRegexGroup.PROTOCOL_AUTHORITY));
    sb.append(getGroup(m, MetaRegexGroup.SLASH_AFTER_AUTHORITY));
    return sb.toString();
  }

  private String buildPathPart(Matcher m) {
    StringBuilder sb = new StringBuilder();
    sb.append("/");
    sb.append(getGroup(m, MetaRegexGroup.FILE));
    return sb.toString();
  }

}
