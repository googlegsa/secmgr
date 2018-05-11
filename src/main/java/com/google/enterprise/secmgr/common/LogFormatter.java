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

package com.google.enterprise.secmgr.common;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

/**
 * A custom log formatter for the Security Manager.  Fits each log message in a
 * single line (assuming the logged message is itself a single line).
 */
public class LogFormatter extends Formatter {

  private static final DateTimeFormatter dateTimeFormatter =
      DateTimeFormat.forPattern("yyMMdd HH:mm:ss.SSS");

  @Override
  public String format(LogRecord rec) {
    StringBuilder buffer = new StringBuilder();

    buffer.append(dateTimeFormatter.print(rec.getMillis()));
    buffer.append(":");

    // One character code for level
    int level = rec.getLevel().intValue();
    if (level <= Level.FINE.intValue()) {
      buffer.append("D");
    } else if (level >= Level.WARNING.intValue()) {
      buffer.append("X");
    } else {
      buffer.append("I");
    }

    Throwable thrown = rec.getThrown();
    if (thrown != null) {
      buffer.append("T");
    }

    buffer.append(" ");

    // Information about the source of the exception
    buffer.append(rec.getThreadID());
    buffer.append(" [");
    buffer.append(shortenClassName(rec.getSourceClassName()));
    buffer.append(".");
    buffer.append(rec.getSourceMethodName());
    buffer.append("] ");
    // Argh, you can't get the source line number.

    // The actual message.
    buffer.append(formatMessage(rec));
    buffer.append("\n");

    // The stack trace.
    if (thrown != null) {
      StringWriter sw = new StringWriter();
      PrintWriter pw = new PrintWriter(sw);
      thrown.printStackTrace(pw);
      pw.flush();
      buffer.append(sw.toString());
    }

    return buffer.toString();
  }

  private static final String MATCH_PREFIX = "com.google.enterprise.secmgr.";
  private static final String REPLACE_PREFIX = ".";

  public static String shortClassName(Class<?> clazz) {
    return shortenClassName(clazz.getName());
  }

  public static String shortenClassName(String className) {
    // Simplify security-manager classes by stripping common prefix.
    return (className.startsWith(MATCH_PREFIX))
        ? REPLACE_PREFIX + className.substring(MATCH_PREFIX.length())
        : className;
  }
}
