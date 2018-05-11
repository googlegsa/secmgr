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

package com.google.enterprise.param.io;

import java.io.*;
import java.util.*;
import java.util.logging.Logger;

/**
 * A simple utility class for storing and retrieving configuration parameters.
 * This class provides a Map-like interface for setting and getting parameter
 * values by name. It also provides read() and write() methods for
 * serializing the Map-like structure to/from a Reader/Writer.
 *
 */
public class ConfigSerializer {
  private static final Logger logger =
    Logger.getLogger(ConfigSerializer.class.getName());
  // Map for storing parameter names and values:
  private Map<String, String> params = null;

  public ConfigSerializer() {
    params = new HashMap<String, String>();
  }

  /**
   * Reads parameter names and values from specified reader.
   * @param reader the Reader to use for reading the parameters.
   * @throws IOException if data can not be read.
   */
  public void read(Reader reader) throws IOException {
    // implementation detail:
    // we expect each parameter name/value pair to be stored on a separate line
    // in the format key:value.
    logger.info("Reading configuration parameters.");
    params.clear();
    BufferedReader in = new BufferedReader(reader);
    String line = null;
    while ((line = in.readLine()) != null) {
      // ignore leading and trailing whitespace:
      line = line.trim();
      // ignore empty lines and lines which may be interpreted as comments:
      if ((line.length() == 0) || (line.charAt(0) == '#'))
        continue;
      // we use a colon to separate key from value:
      int index = line.indexOf(':');
      if (index <= 0) {
        logger.warning("Unable to parse input line: " + line);
        continue;  // key can not be empty string.
      }
      String key = line.substring(0, index).trim();
      String value = (index < line.length() - 1) ?
                     line.substring(index + 1).trim() : "";
      logger.info("Read configuration parameter: " + key + " = " + value);
      if (params.containsKey(key))
        logger.warning("Overwriting previous value for: " + key + "!");
      params.put(key, value);
    }
  }


  /**
   * Writes parameter names and values to the specified writer.
   * @param writer the Writer to use for writing out the parameters.
   * @throws IOException if an error occurs while accessing the Writer.
   */
  public void write(Writer writer) throws IOException {
    logger.info("Writing configuration parameters");
    PrintWriter out = new PrintWriter(writer);
    for (Map.Entry<String, String> entry : params.entrySet()) {
      out.print(entry.getKey());
      out.append(':');
      out.println(entry.getValue());
    }
  }


  /**
   * Set the value of the specified parameter. If this parameter was set before
   * its old value is overridden.
   * @param key the name of the parameter. MUST NOT be null. MUST not contain
   * the special character ':'. MUST NOT begin with the special character '#'.
   * Leading and trailing whitespace will be removed.
   * @param value the value of the parameter.  Leading and trailing whitespace
   * will be removed. If the value is null the entry is removed.
   */
  public void set(String key, String value) {
    key = key.trim();
    if (value == null) {
      // null value: remove entry if it exists.
      logger.fine("Set (remove) key: " + key);
      params.remove(key);
      return;
    }
    value = value.trim();
    if ((key.length() == 0) || (key.indexOf(':') != -1) ||
        (key.charAt(0) == '#')) {
      throw new IllegalArgumentException(
          "Key can not be empty, contain a colon, or start with '#' (" +
          key + ").");
    }
    params.put(key, value);
    logger.fine("Set: " + key + " = " + value);
  }

  /**
   * Return the value of the specified parameter.
   * @param key the name of the parameter.
   * @return the value of the specified parameter, or null if this value is
   * unknown.
   */
  public String get(String key) {
    return params.get(key.trim());
  }


  /**
   * Return the value of the specified parameter, returning the default value
   * if this parameter was not yet set (or read).
   * @param key the name of the parameter.
   * @param def the default value to return if this parameter does not exist.
   * @return the value of the specified parameter, or the default value if the
   * value is unknown.
   */
  public String get(String key, String def) {
    String value = get(key);
    return (value != null) ? value : def;
  }
}
