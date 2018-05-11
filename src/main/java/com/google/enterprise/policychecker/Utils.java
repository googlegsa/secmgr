// Copyright 2007 Google Inc.
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

package com.google.enterprise.policychecker;

import com.google.common.base.Splitter;
import com.google.common.base.Strings;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Stack;
import java.util.regex.Pattern;

/**
 * Utils is a utility class for parsing our ad hoc intermediate format. The
 * format is described in {@link Group}.
 */
public class Utils {

  private Utils() {
    // prevents instantiation
  }

  private static final Pattern COLON_PLUS_WHITESPACE;
  private static final Pattern WHITESPACE;

  static {
    // this pattern means: break at whitespace or at a colon followed by
    // optional
    // whitespace, but in that case, keep the colon on the previous token
    COLON_PLUS_WHITESPACE = Pattern.compile("((?<=:)[\\s]*)|[\\s]+");
    WHITESPACE = Pattern.compile("[\\s]+");
  }

  /**
   * Splits a String on colons or white space, preserving the colon as part of
   * the previous token.
   *
   * @param input a String
   * @return a Stack of String tokens, which may be empty (but not
   *         <code>null</code>)
   */
    public static Stack<String> split(String input) {
      String[] tokens = COLON_PLUS_WHITESPACE.split(input);
      Stack<String> stack = new Stack<String>();
      stackUp(Arrays.asList(tokens), stack);
      return stack;
   }

  /**
   * Splits a String on colons or white space, preserving the colon as part of
   * the previous token for Opaque Acls.
   *
   * For Transparent Acls like group:eng admin right=read user:charlie sheen right=read
   * the following stack will be returned -
   * group:
   * eng admin
   * right=read
   * user:
   * charlie sheen
   * right=read
   *
   * @param input a String
   * @return a Stack of String tokens, which may be empty (but not
   *         <code>null</code>)
   */
  public static Stack<String> splitAclString(String input) {
    Stack<String> stack = new Stack<String>();
    if (input.startsWith("acl:")) {
      return split(input);
    }
    List<String> tokens = Splitter.on(':').trimResults().omitEmptyStrings().splitToList(input);
    
    List<String> fixedTokens = fixTokens(tokens, input.endsWith(":"));
    List<String> finalTokens = new ArrayList<String>();
    
    for (String token : fixedTokens) {
      List<String> subTokens = processToken(token);
      for (String subToken : subTokens) {
        if (subToken != null && subToken.length() > 0) {
          finalTokens.add(subToken);
        }
      }
    }
    stackUp(finalTokens, stack);
    return stack;
  }
    
  private static List<String> fixTokens(List<String> tokens, boolean lastColon) {
    List<String> finalTokens = new ArrayList<String>();
    String newToken = " ";
    for (String token : tokens) {
      newToken += token;
      if (newToken.endsWith(" user") || newToken.endsWith(" group") || newToken.equals("user")
          || newToken.equals("group")) {
        finalTokens.add(newToken + ":");
        newToken = "";
      } else {
        newToken += ":";
      }
    }
    if (!Strings.isNullOrEmpty(newToken)) {
      finalTokens.add(newToken);
    }
    if (!lastColon) {
      int lastIdx = finalTokens.size() - 1;
      String lasttoken = finalTokens.get(lastIdx);
      if (lasttoken.endsWith(":")) {
        finalTokens.set(lastIdx, lasttoken.substring(0, lasttoken.length() - 1));
      }
    }
    return finalTokens;
  }
  
  private static List<String> processToken(String str) {
    List<String> processedStr = new ArrayList<String>();
    // There will be only 1 right= and the first half will either be a user name
    // or a group name. The second half will be the access right (like read) followed by space
    // and then a keyword user: or group: or nothing.
    List<String> tokens = Splitter.on("right=").splitToList(str);
    if (tokens.size() == 2) { 
      processedStr.add(tokens.get(0).trim());
      List<String> rightStr = Splitter.on(' ').trimResults().omitEmptyStrings().
          splitToList(tokens.get(1));
      processedStr.add("right=" + rightStr.get(0).trim());
      if (rightStr.size() == 2) {
        processedStr.add(rightStr.get(1).trim());
      } 
    } else {
      if (tokens.size() == 1) {        
        if (tokens.get(0).endsWith("group:")) {
          // remove the group keyword.
          processedStr.add(tokens.get(0).substring(0, tokens.get(0).length() - 6).trim());
          processedStr.add("group:");
        } else if (tokens.get(0).endsWith("user:")) {
          // remove the user keyword.
          processedStr.add(tokens.get(0).substring(0, tokens.get(0).length() - 5).trim());
          processedStr.add("user:");
        } else {
          processedStr.add(tokens.get(0).trim());
        }
      }
    }
    return processedStr;
  }

  private static void stackUp(List<String> tokens, Stack<String> stack) {
    for (int i = tokens.size() - 1; i >= 0; i--) {
      String token = tokens.get(i);
      if (token != null && token.length() > 0) {
        stack.add(token);
      }
    }
  }

  public static Stack<String> splitOffUrl(String input) {
    String[] tokens = WHITESPACE.split(input,2);    
    Stack<String> stack = new Stack<String>();
    stackUp(Arrays.asList(tokens), stack);
    return stack;
  }

  /**
   * Splits the same way as {@link #split(String)}, but the first token is parsed
   * specially, because it is a URL, and thus might contain :
   * @param input a String
   * @return a Stack of String tokens, which may be empty (but not
   *         <code>null</code>)
   */
  public static Stack<String> splitWithFirstTokenUrl(String input) {
    Stack<String> tokens = splitOffUrl(input);
    if (tokens.isEmpty()) {
      return tokens;
    }
    String url = tokens.pop();
    if (!tokens.isEmpty()) {
      input = tokens.pop();
      tokens = split(input);
    }
    tokens.add(url);
    return tokens;
  }
 
  
  /**
   * Reads a line from a BufferedReader, skipping comment lines (lines beginning
   * with '#').
   * 
   * @param reader a BufferedReader
   * @return a String or <code>null</code> if there were no lines left
   */
  public static String readLine(BufferedReader reader) {
    String str = readLineSimple(reader);
    if (str == null) {
      return null;
    }
    while (str.startsWith("#")) {
      str = readLineSimple(reader);
      if (str == null) {
        return null;
      }
    }
    return str;
  }

  private static String readLineSimple(BufferedReader reader) {
    String str = null;
    try {
      str = reader.readLine();
    } catch (IOException e) {
      // TODO: add proper logging
      e.printStackTrace();
    }
    return str;
  }
}
