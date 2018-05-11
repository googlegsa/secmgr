// Copyright 2010 Google Inc.
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
import com.google.enterprise.secmgr.common.Base64;
import com.google.enterprise.secmgr.common.Base64DecoderException;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.inject.Singleton;

import com.google.protobuf.InvalidProtocolBufferException;
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
 * A facet to access deny rules.
 *
 */
@ThreadSafe
@Singleton
public class DenyRules implements DenyRulesInterface {
  private static final Logger logger =
      Logger.getLogger(DenyRules.class.getName());

  @GuardedBy("this") private MappingFromPatternMatcher<Entry<String, DenyRule>> rulesMap;

  @GuardedBy("this") private String confFilename = null;
  /** The modification time of the configuration file when last read. */
  @GuardedBy("this") private long configTime;

  @VisibleForTesting
  @Inject
  DenyRules() {
    SequentialRegexPatternMatcher fm = new SequentialRegexPatternMatcher(new AtomicInteger(0));
    rulesMap = new MappingFromPatternMatcher<Entry<String, DenyRule>>(fm);
  }

  private synchronized boolean changedConfig()
      throws FileNotFoundException {
    boolean changed = false;
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
   * Gets the matching deny rule for the url.
   *
   * @param urlString The url
   * @return The deny rule, or null if there is no match.
   */
  public DenyRule getRule(String urlString) {
    try {
      loadifChanged();
    } catch (IOException e) {
      logger.log(Level.SEVERE, "Failed to load deny rules.", e);
      e.printStackTrace();
    }
    Entry<String, DenyRule> entry = rulesMap.getBestValue(urlString);
    return (entry == null) ? null : entry.getValue();
  }

  /**
   * Reads the deny rules from config file and populates the internal map.
   */
  private void loadifChanged() throws IOException {
    if (confFilename == null) {
      confFilename = ConfigSingleton.getConfig().getDenyRulesFilename();
    }
    try {
      while (changedConfig()) {
        reset();
        load();
      }
    } catch (FileNotFoundException e) {
      logger.warning("Could not find deny rules conf file: " + confFilename);
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
      logger.info("Deny rules loaded from: " + confFilename);
    } catch (FileNotFoundException e) {
      logger.warning("Could not find deny rules conf file: " + confFilename);
    } finally {
      fileReader.close();
    }
  }

  private synchronized void reset() {
    SequentialRegexPatternMatcher fm = new SequentialRegexPatternMatcher(new AtomicInteger(0));
    rulesMap = new MappingFromPatternMatcher<Entry<String, DenyRule>>(fm);
  }

  /**
   * Parses a deny rule entry.
   *
   * @param entry a deny rule config
   * @return the deny rule object.
   */
  private DenyRule parse(String entry) {
    if (CharMatcher.whitespace().trimFrom(entry).isEmpty()) {
      logger.info("Empty deny rule ");
      return null;
    }

    String[] tokens = Iterables.toArray(Splitter.on(' ').split(entry), String.class);
    if (tokens.length != 2) {
      logger.severe("Unsupported deny rule " + entry);
      return null;
    }

    String urlPattern = tokens[0];
    DenyRule.Builder denyRuleBuilder = DenyRule.newBuilder();

    try {
      denyRuleBuilder.mergeFrom(Base64.decode(tokens[1]));
    } catch (Base64DecoderException | InvalidProtocolBufferException ignored) {
      logger.severe("Failed to decode deny rule content: " + tokens[1]);
      return null;
    }

    logger.info("Read deny rule " + urlPattern);
    DenyRule denyRule = denyRuleBuilder.build();
    Entry<String, DenyRule> ruleEntry = Maps.immutableEntry(urlPattern, denyRule);
    rulesMap.put(urlPattern, ruleEntry);
    return denyRule;
  }

  @VisibleForTesting
  synchronized void setConfFile(String filename) {
    confFilename = filename;
  }
}
