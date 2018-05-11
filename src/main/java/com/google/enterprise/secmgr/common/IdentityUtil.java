// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.secmgr.common;

import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * Utility functions for Identity.
 * 
 *
 */
public class IdentityUtil {

  /**
   * Parses a string into a username/domain pair.
   * This logic should be kept in sync with google3/enterprise/supergsa/security/acl_utils.cc
   * 
   * @param string The combined username/domain string.
   * @return The username and domain strings as an array.
   */
  @Nonnull
  public static String[] parseNameAndDomain(String string) {
    Preconditions.checkNotNull(string);
    int slash = string.indexOf("\\");
    if (slash == -1) {
      slash = string.indexOf("/");
    }
    if (slash >= 0) {
      return new String[] { string.substring(slash + 1), string.substring(0, slash) };
    }
    int atSign = string.indexOf("@");
    if (atSign >= 0) {
      return new String[] { string.substring(0, atSign), string.substring(atSign + 1) };
    }
    return new String[] { string, null };
  }

  /**
   * Joins a username and domain into a string.
   *
   * @param username The username.
   * @param domain The domain, or {@code null} if none.
   * @return The combined username/domain string.
   */
  @Nonnull
  public static String joinNameDomain(String username, @Nullable String domain) {
    Preconditions.checkNotNull(username);
    return (Strings.isNullOrEmpty(domain)) ? username : username + "@" + domain;
  }

  public static String normalizeDomain(String domain) {
    if (Strings.isNullOrEmpty(domain)) {
      return null;
    }    
    Iterable<String> str = Splitter.on('.').trimResults().omitEmptyStrings().split(domain);
    for (String substr : str) {
      return substr;
    }
    return domain;
  }
}
