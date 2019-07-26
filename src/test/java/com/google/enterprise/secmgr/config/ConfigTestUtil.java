// Copyright 2009 Google Inc.
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

package com.google.enterprise.secmgr.config;

import com.google.common.base.Function;
import com.google.common.collect.Iterables;
import java.util.Arrays;

/**
 * Unit test utilities for config.
 */
public final class ConfigTestUtil {

  // Don't instantiate
  private ConfigTestUtil() {
    throw new UnsupportedOperationException();
  }

  public static String jsonArray(String... elts) {
    return jsonArray(Arrays.asList(elts));
  }

  public static String jsonArray(Iterable<String> elts) {
    return commaSeparated("[", "]", elts);
  }

  public static String jsonObject(String... bindings) {
    return jsonObject(Arrays.asList(bindings));
  }

  public static String jsonObject(Iterable<String> bindings) {
    return commaSeparated("{", "}", bindings);
  }

  private static String commaSeparated(String prefix, String suffix, Iterable<String> elts) {
    if (Iterables.isEmpty(elts)) {
      return prefix + suffix;
    }
    StringBuilder buffer = new StringBuilder();
    for (String elt : elts) {
      buffer.append(prefix);
      prefix = ",";
      buffer.append(elt);
    }
    buffer.append(suffix);
    return buffer.toString();
  }

  public static String jsonBinding(String key, String value) {
    return jsonQuote(key) + ":" + value;
  }

  public static String jsonBinding(String key, boolean value) {
    return jsonQuote(key) + ":" + value;
  }

  public static String jsonBinding(String key, int value) {
    return jsonQuote(key) + ":" + value;
  }

  public static String jsonBinding(String key, long value) {
    return jsonQuote(key) + ":" + value;
  }

  public static String jsonStringArray(String... strings) {
    return jsonStringArray(Arrays.asList(strings));
  }

  public static String jsonStringArray(Iterable<String> strings) {
    return jsonArray(
        Iterables.transform(strings,
            new Function<String, String>() {
              public String apply(String string) {
                return jsonQuote(string);
              }
            }));
  }

  public static String jsonQuote(String string) {
    if (string == null) {
      return "null";
    }
    StringBuilder buffer = new StringBuilder();
    buffer.append("\"");
    for (int i = 0; i < string.length(); i++) {
      char c = string.charAt(i);
      if (c == '\\' || c == '"') {
        buffer.append("\\");
      }
      buffer.append(c);
    }
    buffer.append("\"");
    return buffer.toString();
  }

  public static String jsonQuote(int n) {
    return Integer.toString(n);
  }

  public static String jsonQuote(boolean b) {
    return Boolean.toString(b);
  }
}
