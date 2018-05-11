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

package com.google.enterprise.util;

import com.google.common.base.Joiner;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

/**
 * Utilities to parse aspects of HTTP requests.
 */
public class HttpUtil {

  public static final String NO_VALUE_MESSAGE = "<no value present for header>";
  public static final String SEP = ": ";

  public static List<String> extractHeaders(HttpServletRequest request) {
    List<String> headers = new ArrayList<>();
    if (request == null) {
      return null;
    }

    Enumeration<String> headerKeys = request.getHeaderNames();
    if (headerKeys != null) {
      while (headerKeys.hasMoreElements()) {
        String key = headerKeys.nextElement();
        Enumeration<String> headerVals = request.getHeaders(key);
        if (headerVals != null) {
          while (headerVals.hasMoreElements()) {
            String val = headerVals.nextElement();
            if (val != null) {
              headers.add(key + SEP + val);
            } else {
              headers.add(key + SEP + NO_VALUE_MESSAGE);
            }
          }
        } else {
          headers.add(key + SEP + NO_VALUE_MESSAGE);
        }
      }
    }
    return headers;
  }

  public static String extractHeaderString(HttpServletRequest request) {
    return joiner(extractHeaders(request));
  }

  private static String joiner(List<String> strList) {
    if (strList == null) {
      return null;
    }
    Joiner strJoiner = Joiner.on("\n");
    return strJoiner.join(strList);
  }
}
