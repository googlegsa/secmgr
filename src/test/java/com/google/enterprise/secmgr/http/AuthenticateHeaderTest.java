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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableListMultimap;
import junit.framework.TestCase;

/**
 * Unit tests for {@link AuthenticateHeader}.
 */
public final class AuthenticateHeaderTest extends TestCase {

  private static final String PARAM_NAME_REALM = "realm";
  private static final String PARAM_VALUE_MY_REALM = "MY.REALM";

  private static final ImmutableList<String> GOOD_TOKENS =
      ImmutableList.of("Basic", "a", "0", "foobar", "foo_bar");

  private static final ImmutableList<String> BAD_TOKENS =
      ImmutableList.of("", "@", "foo,bar", "foo bar");

  public void testParseCombinations() { // 2273 unique cases
    for (String scheme : GOOD_TOKENS) {
      testSingleParse(true, scheme);
      testParseCombosWithScheme(true, scheme);
    }
    for (String scheme : BAD_TOKENS) {
      testParseCombosWithScheme(false, scheme);
    }
  }

  private static void testParseCombosWithScheme(boolean isParsable,
      String scheme) {
    for (String realm : GOOD_TOKENS) {
      testSingleParse(isParsable, scheme, PARAM_NAME_REALM, realm);
    }
    for (String realm : BAD_TOKENS) {
      testSingleParse(false, scheme, PARAM_NAME_REALM, realm);
    }
    for (String paramName : GOOD_TOKENS) {
      testParseCombosWithParam(isParsable, scheme, paramName);
    }
    for (String paramName : BAD_TOKENS) {
      testParseCombosWithParam(false, scheme, paramName);
    }
  }

  private static void testParseCombosWithParam(boolean isParsable,
      String scheme, String paramName) {
    for (String paramValue : GOOD_TOKENS) {
      testParseCombosWithParamHelper(isParsable, scheme, paramName, paramValue);
    }
    for (String paramValue : BAD_TOKENS) {
      testParseCombosWithParamHelper(false, scheme, paramName, paramValue);
    }
  }

  private static void testParseCombosWithParamHelper(boolean isParsable,
      String scheme, String paramName, String paramValue) {
    testSingleParse(false, scheme, paramName, paramValue);
    testSingleParse(isParsable, scheme, paramName, paramValue,
        PARAM_NAME_REALM, PARAM_VALUE_MY_REALM);
    testSingleParse(isParsable, scheme, PARAM_NAME_REALM, PARAM_VALUE_MY_REALM,
        paramName, paramValue);
  }

  private static void testSingleParse(boolean isParsable, String scheme,
      String... paramStrings) {
    String input = makeInputString(scheme, paramStrings);
    if (isParsable) {
      AuthenticateHeader expected = makeExpected(scheme, paramStrings);
      assertEquals(expected, AuthenticateHeader.parse(input));
    } else {
      try {
        AuthenticateHeader.parse(input);
        fail("parse accepted an invalid input: " + input);
      } catch (IllegalArgumentException e) {
        // correctly rejected bad input
      }
    }
  }

  /** Manually construct a header value string from its components. */
  private static String makeInputString(String authScheme,
      String... paramStrings) {
    Preconditions.checkArgument((paramStrings.length % 2) == 0);
    StringBuilder builder = new StringBuilder();
    builder.append(authScheme);
    String prefix = " ";
    for (int i = 0; i < paramStrings.length; i += 2) {
      builder.append(prefix);
      prefix = ",";
      builder.append(paramStrings[i]);
      builder.append("=");
      builder.append(paramStrings[i + 1]);
    }
    return builder.toString();
  }

  /** Manually construct an AuthenticateHeader from its components. */
  private static AuthenticateHeader makeExpected(String authScheme,
      String... paramStrings) {
    ImmutableListMultimap.Builder<String, String> builder
      = ImmutableListMultimap.builder();
    Preconditions.checkArgument((paramStrings.length % 2) == 0);
    String realm = null;
    for (int i = 0; i < paramStrings.length; i += 2) {
      builder.put(paramStrings[i], paramStrings[i + 1]);
      if (PARAM_NAME_REALM.equals(paramStrings[i]) && realm == null) {
        realm = paramStrings[i + 1];
      }
    }
    return AuthenticateHeader.makeForTest(authScheme, realm, builder.build());
  }

  public void testUpperCaseRealm() {
    AuthenticateHeader ah = AuthenticateHeader.parse("Basic Realm=Basic");
    String realm = ah.getRealm();
    assertEquals("Basic", realm);
  }

  public void testUpperCaseRealm2() {
    AuthenticateHeader ah = AuthenticateHeader.parse("Basic REALM=Basic");
    String realm = ah.getRealm();
    assertEquals("Basic", realm);
  }

  public void testUpperCaseRealm3() {
    AuthenticateHeader ah = AuthenticateHeader.parse("Basic rEAlM=Basic");
    String realm = ah.getRealm();
    assertEquals("Basic", realm);
  }
}
