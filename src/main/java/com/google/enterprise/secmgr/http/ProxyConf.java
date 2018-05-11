// Copyright 2013 Google Inc.
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

package com.google.enterprise.secmgr.http;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.common.labs.matcher.MappingFromPatternMatcher;
import com.google.common.labs.matcher.SequentialRegexPatternMatcher;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.inject.Singleton;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;

/**
 * A facet to access pattern based proxy configuration.
 *
 */
@ThreadSafe
@Singleton
public class ProxyConf implements ProxyConfInterface {
  private static final Logger logger =
      Logger.getLogger(ProxyConf.class.getName());

  @GuardedBy("this") private MappingFromPatternMatcher<Entry<String, String>> proxyMap;

  @GuardedBy("this") private String confFilename = null;

  // The modification time of the configuration file when last read.
  @GuardedBy("this") private long configTime;

  @VisibleForTesting
  @Inject
  ProxyConf() {
    SequentialRegexPatternMatcher fm = new SequentialRegexPatternMatcher(new AtomicInteger(0));
    proxyMap = new MappingFromPatternMatcher<Entry<String, String>>(fm);
  }

  private synchronized boolean changedConfig()
      throws FileNotFoundException {
    File file = FileUtil.getContextFile(confFilename);
    long time = file.lastModified();
    if (time == 0) {
      throw new FileNotFoundException("No such file: " + file);
    }
    if (time == configTime) {
      return false;
    }
    configTime = time;
    return true;
  }

  /**
   * Gets the proxy for the url.
   *
   * @param urlString The url
   * @return The proxy, or null if there is no match.
   */
  public String getProxy(String urlString) {
    try {
      loadIfChanged();
    } catch (IOException e) {
      logger.log(Level.SEVERE, "Failed to load proxy conf file.", e);
      e.printStackTrace();
    }
    Entry<String, String> entry = proxyMap.getBestValue(urlString);
    return (entry == null) ? null : entry.getValue();
  }

  /**
   * Reads the proxy configuration from config file and populates the internal map.
   */
  private void loadIfChanged() throws IOException {
    if (confFilename == null) {
      confFilename = ConfigSingleton.getConfig().getProxyConfFilename();
    }
    try {
      while (changedConfig()) {
        reset();
        load();
      }
    } catch (FileNotFoundException e) {
      logger.warning("Could not find  proxy confs conf file: " + confFilename);
    }
  }

  private void load() throws IOException {
    File file = FileUtil.getContextFile(confFilename);
    FileReader fileReader = new FileReader(file);
    try {
      BufferedReader bufferedReader = new BufferedReader(fileReader);
      while (true) {
        String line = bufferedReader.readLine();
        if (line == null) {
          break;
        }
        parse(line);
      }
      logger.info("Proxy configuration loaded from: " + confFilename);
    } catch (FileNotFoundException e) {
      logger.warning("Could not find proxy conf file: " + confFilename);
    } finally {
      fileReader.close();
    }
  }

  private synchronized void reset() {
    SequentialRegexPatternMatcher fm = new SequentialRegexPatternMatcher(new AtomicInteger(0));
    proxyMap = new MappingFromPatternMatcher<Entry<String, String>>(fm);
  }

  /**
   * Parses a proxy conf entry and put into the proxy map.
   *
   * @param entry a proxy config
   * @return void.
   */
  private void parse(String entry) {
    if (CharMatcher.whitespace().trimFrom(entry).isEmpty()) {
      logger.info("Empty proxy conf");
      return;
    }

    String[] tokens = Iterables.toArray(Splitter.on(' ').split(entry), String.class);
    if (tokens.length != 2) {
      logger.severe("Unsupported proxy conf " + entry);
      return;
    }

    logger.info("Read proxy conf " + entry);
    Entry<String, String> conf = Maps.immutableEntry(tokens[0], tokens[1]);

    proxyMap.put(tokens[0], conf);
  }

  @VisibleForTesting
  synchronized void setConfFile(String filename) {
    confFilename = filename;
  }
}
