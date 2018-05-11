/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.enterprise.secmgr.http;

import com.google.common.annotations.VisibleForTesting;

import java.net.URL;
import java.util.Iterator;
import java.util.Map;
import java.util.NavigableMap;
import java.util.concurrent.ConcurrentSkipListMap;

/**
 * Tracks handlers with known authn schemes.
 */
class KnownAuthSchemers {
  private final NavigableMap<String, String> known; 

  @VisibleForTesting
  KnownAuthSchemers() {
    known = new ConcurrentSkipListMap<String, String>();
  }

  @VisibleForTesting
  Map<String, String> getBackingMapForTest() {
    return known;
  }

  @VisibleForTesting
  static String makePathToHandler(URL url) {
    StringBuilder handlerPath =  new StringBuilder(url.getProtocol());
    handlerPath.append("://");
    // ignore user-info part of url
    handlerPath.append(url.getHost());
    int port = url.getPort();
    if (-1 != port) {
      handlerPath.append(":").append(port);
    }
    String path = url.getPath();
    if (0 == path.length()) {
      handlerPath.append("/");
    } else {
      if (path.startsWith("/")) {
        handlerPath.append(path);
      } else {
        String err = "url.getPath that does not start with / found in " + url;
        throw new AssertionError(err);
      }
    }
    // ignore query and fragment parts of url

    // now chop down to handler part and end it with slash
    int index = handlerPath.toString().lastIndexOf("/");
    if (index > 0) {
      return handlerPath.toString().substring(0, index + 1);
    } else {
      String err = "handler path without / made from " + url;
      throw new AssertionError(err);
    }
  }

  /** Currently supports only "Basic" scheme. All others ignored. */
  void addKnown(final URL url, final String scheme) {
    if ("Basic".equals(scheme)) {
      if (isKnownBasic(url)) {
        // url is under existing known paths; no need to add
        return;
      }
      String pathToHandler = makePathToHandler(url);
      known.put(pathToHandler, "Basic");

      // all paths under current path just added are unnecessary so remove them
      Iterator<Map.Entry<String, String>> tail
          = known.tailMap(pathToHandler).entrySet().iterator();
      while (tail.hasNext()) {
        Map.Entry<String, String> e = tail.next();
        if (pathToHandler.equals(e.getKey())) {
          // skip entry just added
        } else if (e.getKey().startsWith(pathToHandler)) {
          tail.remove();
        } else {
          break;
        }
      }
    }
  }

  /** True if definately known to be "Basic", otherwise false. */
  boolean isKnownBasic(URL url) {
    String handlerPath = makePathToHandler(url);
    Map.Entry<String, String> e = known.floorEntry(handlerPath);
    if (e != null && handlerPath.startsWith(e.getKey())) {
      // currently supporting http-basic; class is ready for ntlm etc.
      return "Basic".equals(e.getValue());
    }
    return false;
  }

  private static final KnownAuthSchemers SINGLETON = new KnownAuthSchemers();

  static KnownAuthSchemers getInstance() {
    return SINGLETON;
  }
}
