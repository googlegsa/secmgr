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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Function;
import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.enterprise.secmgr.generators.Generator;
import com.google.enterprise.secmgr.generators.Generators;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import junit.framework.Test;
import junit.framework.TestCase;

/**
 * Unit tests for cookie-header parsing.
 */
public final class GCookieParserTest extends TestCase {
  private static final Logger logger = Logger.getLogger(GCookieParserTest.class.getName());

  private static final URI URI1 = URI.create("http://home.example.org:8888/cookie-parser-result");

  private static JsonElement readJsonFile(String filename)
      throws IOException {
    Reader reader =
        Files.newBufferedReader(
            Paths.get(GCookieParserTest.class.getResource(filename).getFile()), UTF_8);
    try {
      return new JsonParser().parse(reader);
    } finally {
      reader.close();
    }
  }

  private static List<Test> convertJsonTests(JsonElement testsElement,
      Function<JsonElement, Test> converter) {
    ImmutableList.Builder<Test> testsBuilder = ImmutableList.builder();
    for (JsonElement entryElement : testsElement.getAsJsonArray()) {
      testsBuilder.add(converter.apply(entryElement));
    }
    return testsBuilder.build();
  }

  private static Supplier<String> testNameGenerator(final String prefix) {
    return new Supplier<String>() {
      private int i = 1;

      @Override
      public String get() {
        return prefix + i++;
      }
    };
  }

  public void testParseNull() {
    try {
      tryParseRequest1(-1, null);
      fail();
    } catch (NullPointerException e) {
      // pass
    }
  }

  public void testParseEmpty() {
    for (Object header : whitespaceWrapper("")) {
      tryParseRequest(0, header);
    }
  }

  public void testParseSimple() {
    tryOneGood("foobar", "bazmum");
  }

  public void testParseNoEquals() {
    for (Object header : whitespaceWrapper("foobar")) {
      tryParseRequest(0, header);
    }
  }

  public void testParseNoValue() {
    tryOneGood("foobar", "");
  }

  public void testParseEqualsOnly() {
    tryOneBad("", "");
  }

  public void testParseNoName() {
    tryOneBad("", "bazmum");
  }

  private void tryOneGood(String nameBase, String valueBase) {
    for (Object[] product :
             Generators.crossProductIterable(
                 nameGenerator(nameBase),
                 valueGenerator(valueBase))) {
      String name = flattenStrings(product[0]);
      String value = flattenStrings(product[1]);
      for (Object[] header :
               Generators.crossProductIterable(
                   whitespaceWrapper(name),
                   whitespaceWrapper(value))) {
        CookieStore cookies = tryParseRequest(1, header[0], "=", header[1]);
        assertCookie(value, cookies.get(name));
      }
    }
  }

  private void tryOneBad(String nameBase, String valueBase) {
    for (Object[] product :
             Generators.crossProductIterable(
                 nameGenerator(nameBase),
                 valueGenerator(valueBase))) {
      for (Object[] header :
               Generators.crossProductIterable(
                   whitespaceWrapper(flattenStrings(product[0])),
                   whitespaceWrapper(flattenStrings(product[1])))) {
        tryParseRequest(0, header[0], "=", header[1]);
      }
    }
  }

  // Above tests try lots of variants with weird characters.  The remaining
  // tests don't do these variants, because it would take too long.  For
  // example, testParseSimple takes about 5 seconds at present; extending the
  // same test for two cookies would square the time.  So from here on in we
  // just vary whitespace and number of cookie bindings.  This is sensible
  // because the cookie parser splits the input by semi-colons, then parses each
  // chunk individually.  So we test the individual parser carefully, then make
  // sure that combinations work OK.

  public void testTwoOk() {
    String name1 = "foobar";
    String value1 = "bazmum";
    String name2 = "barfoo";
    String value2 = "mumble";
    for (Object[] product :
             Generators.crossProductIterable(
                 whitespaceWrapper(name1),
                 whitespaceWrapper(value1),
                 whitespaceWrapper(name2),
                 whitespaceWrapper(value2))) {
      CookieStore cookies =
          tryParseRequest(2,
              product[0], "=", product[1], ";",
              product[2], "=", product[3]);
      assertCookie(value1, cookies.get(name1));
      assertCookie(value2, cookies.get(name2));
    }
  }

  public void testTwoFirstEmpty() {
    String name = "barfoo";
    String value = "mumble";
    for (Object[] product :
             Generators.crossProductIterable(
                 whitespaceWrapper(""),
                 whitespaceWrapper(name),
                 whitespaceWrapper(value))) {
      CookieStore cookies = tryParseRequest(1, product[0], ";", product[1], "=", product[2]);
      assertCookie(value, cookies.get(name));
    }
  }

  public void testTwoFirstBad() {
    String name = "barfoo";
    String value = "mumble";
    for (Object[] product :
             Generators.crossProductIterable(
                 whitespaceWrapper("foobar"),
                 whitespaceWrapper(name),
                 whitespaceWrapper(value))) {
      CookieStore cookies = tryParseRequest(1, product[0], ";", product[1], "=", product[2]);
      assertCookie(value, cookies.get(name));
    }
  }

  public void testTwoSecondEmpty() {
    String name = "foobar";
    String value = "bazmum";
    for (Object[] product :
             Generators.crossProductIterable(
                 whitespaceWrapper(name),
                 whitespaceWrapper(value),
                 whitespaceWrapper(""))) {
      CookieStore cookies = tryParseRequest(1, product[0], "=", product[1], ";", product[2]);
      assertCookie(value, cookies.get(name));
    }
  }

  public void testTwoSecondBad() {
    String name = "foobar";
    String value = "bazmum";
    for (Object[] product :
             Generators.crossProductIterable(
                 whitespaceWrapper(name),
                 whitespaceWrapper(value),
                 whitespaceWrapper("barfoo"))) {
      CookieStore cookies = tryParseRequest(1, product[0], "=", product[1], ";", product[2]);
      assertCookie(value, cookies.get(name));
    }
  }

  public void testTwoBothEmpty() {
    for (Object[] product :
             Generators.crossProductIterable(
                 whitespaceWrapper(""),
                 whitespaceWrapper(""))) {
      tryParseRequest(0, product[0], ";", product[1]);
    }
  }

  public void testTwoBothBad() {
    for (Object[] product :
             Generators.crossProductIterable(
                 whitespaceWrapper("foobar"),
                 whitespaceWrapper("barfoo"))) {
      tryParseRequest(0, product[0], ";", product[1]);
    }
  }

  public void testThreeOk() {
    String name1 = "foobar";
    String value1 = "bazmum";
    String name2 = "barfoo";
    String value2 = "mumble";
    String name3 = "whats_up";
    String value3 = "dont_know";
    for (Object[] product :
             Generators.crossProductIterable(
                 whitespaceWrapper(name1),
                 whitespaceWrapper(value1),
                 whitespaceWrapper(name2),
                 whitespaceWrapper(value2),
                 whitespaceWrapper(name3),
                 whitespaceWrapper(value3))) {
      CookieStore cookies
          = tryParseRequest(3,
              product[0], "=", product[1], ";",
              product[2], "=", product[3], ";",
              product[4], "=", product[5]);
      assertCookie(value1, cookies.get(name1));
      assertCookie(value2, cookies.get(name2));
      assertCookie(value3, cookies.get(name3));
    }
  }

  public void testThreeMiddleEmpty() {
    String name1 = "foobar";
    String value1 = "bazmum";
    String name3 = "whats_up";
    String value3 = "dont_know";
    for (Object[] product :
             Generators.crossProductIterable(
                 whitespaceWrapper(name1),
                 whitespaceWrapper(value1),
                 whitespaceWrapper(""),
                 whitespaceWrapper(name3),
                 whitespaceWrapper(value3))) {
      CookieStore cookies
          = tryParseRequest(2,
              product[0], "=", product[1], ";",
              product[2], ";",
              product[3], "=", product[4]);
      assertCookie(value1, cookies.get(name1));
      assertCookie(value3, cookies.get(name3));
    }
  }

  public void testThreeMiddleBad() {
    String name1 = "foobar";
    String value1 = "bazmum";
    String name3 = "whats_up";
    String value3 = "dont_know";
    for (Object[] product :
             Generators.crossProductIterable(
                 whitespaceWrapper(name1),
                 whitespaceWrapper(value1),
                 whitespaceWrapper("barfoo"),
                 whitespaceWrapper(name3),
                 whitespaceWrapper(value3))) {
      CookieStore cookies
          = tryParseRequest(2,
              product[0], "=", product[1], ";",
              product[2], ";",
              product[3], "=", product[4]);
      assertCookie(value1, cookies.get(name1));
      assertCookie(value3, cookies.get(name3));
    }
  }

  public void testThreeAllEmpty() {
    for (Object[] product :
             Generators.crossProductIterable(
                 whitespaceWrapper(""),
                 whitespaceWrapper(""),
                 whitespaceWrapper(""))) {
      tryParseRequest(0, product[0], ";", product[1], ";", product[2]);
    }
  }

  /** Demonstration of acceptable and direct use. */
  public void testCookieWithSpace() {
    // Setup cookie line.
    String line = "Cookie: cookie1=I love Spaces; GSA_SESSION_ID=5b0c9d8dccf9977c1ef158257f32e7b6;";
    // Strip http key.
    line = line.substring("Cookie: ".length());

    // Apply.
    CookieStore parsed = tryParseRequest1(2, line);
    assertCookie("I love Spaces", parsed.get("cookie1"));
    assertCookie("5b0c9d8dccf9977c1ef158257f32e7b6", parsed.get("GSA_SESSION_ID"));
  }

  // **************** Request-parser infrastructure ****************

  private CookieStore tryParseRequest(int nCookies, Object... objects) {
    return tryParseRequest1(nCookies, flattenStrings(objects));
  }

  private CookieStore tryParseRequest1(int nCookies, String header) {
    CookieStore store = GCookie.makeStore();
    List<String> headers = Lists.newArrayList();
    headers.add(header);
    GCookie.parseRequestHeaders(headers, store);
    assertEquals(nCookies, store.size());
    return store;
  }

  private void assertCookie(String value, GCookie cookie) {
    assertNotNull(cookie);
    assertEquals(value, cookie.getValue());
  }

  private static Generator whitespaceWrapper(String base) {
    return base.isEmpty()
        ? WHITESPACE_GENERATOR
        : Generators.join(
            WHITESPACE_GENERATOR,
            Generators.of(base),
            WHITESPACE_GENERATOR);
  }

  private static Generator nameGenerator(String nameBase) {
    Generator constant = Generators.of(nameBase);
    return nameBase.isEmpty()
        ? constant
        : Generators.join(NAME_VARIANTS, constant, NAME_VARIANTS);
  }

  private static Generator valueGenerator(String valueBase) {
    Generator constant = Generators.of(valueBase);
    return valueBase.isEmpty()
        ? constant
        : Generators.join(VALUE_VARIANTS, constant, VALUE_VARIANTS);
  }

  private static String flattenStrings(Object... objects) {
    StringBuffer buffer = new StringBuffer();
    flattenStringsWalk(objects, buffer);
    return buffer.toString();
  }

  private static void flattenStringsWalk(Object object, StringBuffer buffer) {
    if (object == null) {
      return;
    }
    if (object instanceof String) {
      buffer.append((String) object);
    } else {
      for (Object elt : Object[].class.cast(object)) {
        flattenStringsWalk(elt, buffer);
      }
    }
  }

  // **************** Constant generators ****************

  private static final Generator WHITESPACE_GENERATOR = Generators.of(null, " \t");

  private static Generator encodingsGenerator(Character... exclusions) {
    List<Character> forbidden = ImmutableList.copyOf(exclusions);
    List<String> encodings = Lists.newArrayList();
    encodings.add(null);
    encodings.add("%20");
    for (char c = 0; c < 0x80; c++) {
      if (!(forbidden.contains(c) ||
              charsToElide.contains(c) ||
              Character.isISOControl(c) ||
              Character.isWhitespace(c) ||
              Character.isLetterOrDigit(c))) {
        encodings.add(String.valueOf(c));
      }
    }
    return Generators.of(encodings);
  }

  // Eliminating these characters speeds up the testing by a large factor.
  // The test speed is proportional to the square of the number of encodings.
  private static final List<Character> charsToElide =
      ImmutableList.of('~', '!', '@', '#', '^', '&', '*', '_', '-', '+', '.', '/');

  private static final Generator NAME_VARIANTS = encodingsGenerator('%', ';', ',', '=', '$');
  private static final Generator VALUE_VARIANTS = encodingsGenerator('%', ';', ',');

  // **************** Date-parser tests ****************

  // Tests taken from http-state working group git repository:
  // https://github.com/abarth/http-state/

  public void testDateParserBsd()
      throws IOException {
    SecurityManagerTestCase.runTestCases(dateParserTestCases("/bsd-examples.json"));
  }

  public void testDateParserOther()
      throws IOException {
    SecurityManagerTestCase.runTestCases(dateParserTestCases("/examples.json"));
  }

  private static List<Test> dateParserTestCases(String filename)
      throws IOException {
    final Supplier<String> names = testNameGenerator("dateTest");
    return convertJsonTests(readJsonFile(filename),
        new Function<JsonElement, Test>() {
          @Override
          public Test apply(JsonElement entryElement) {
            JsonObject entryObject = entryElement.getAsJsonObject();
            JsonElement expectedElement = entryObject.get("expected");
            JsonElement inputElement = entryObject.get("test");
            String expected = expectedElement.isJsonNull() ? null : expectedElement.getAsString();
            String input = inputElement.getAsString();
            return dateParserTest(names.get(), expected, input);
          }
        });
  }

  private static Test dateParserTest(String name, final String expected, final String input) {
    return new TestCase(name) {
      @Override
      public void runTest() {
        String actual;
        try {
          actual = HttpUtil.generateHttpDate(GCookie.parseDate(input));
        } catch (IllegalArgumentException e) {
          logger.info("Parse error during test: " + e.getMessage());
          actual = null;
        }
        assertEquals("For input " + Stringify.object(input) + ": ", expected, actual);
      }
    };
  }

  // **************** Response-parser infrastructure ****************

  // Tests taken from http-state working group git repository:
  // https://github.com/abarth/http-state/

  public void testParser()
      throws IOException {
    SecurityManagerTestCase.runTestCases(parserTestCases("/parser.json"));
  }

  private static List<Test> parserTestCases(String filename)
      throws IOException {
    return convertJsonTests(readJsonFile(filename),
        new Function<JsonElement, Test>() {
          @Override
          public Test apply(JsonElement entryElement) {
            JsonObject entryObject = entryElement.getAsJsonObject();
            logger.info("parsing object: " + entryObject);
            String testName = entryObject.get("test").getAsString();
            ImmutableList.Builder<String> headersBuilder = ImmutableList.builder();
            for (JsonElement element : entryObject.get("received").getAsJsonArray()) {
              headersBuilder.add(element.getAsString());
            }
            List<String> headers = headersBuilder.build();
            ImmutableSet.Builder<GCookie> expectedBuilder = ImmutableSet.builder();
            for (JsonElement element : entryObject.get("sent").getAsJsonArray()) {
              JsonObject object = element.getAsJsonObject();
              expectedBuilder.add(
                  GCookie.make(
                      object.get("name").getAsString(),
                      object.get("value").getAsString()));
            }
            Set<GCookie> expected = expectedBuilder.build();
            JsonElement sentToElement = entryObject.get("sent-to");
            String sentTo = (sentToElement != null)
                ? sentToElement.getAsString()
                : null;
            return parserTest(testName, headers, expected, sentTo);
          }
        });
  }

  private static Test parserTest(final String name, final List<String> headers,
      final Set<GCookie> expected, final String sentTo) {
    final URI responseUri = URI.create(URI1.toString() + "?" + name);
    final URI requestUri = (sentTo != null)
        ? responseUri.resolve(sentTo)
        : responseUri;
    return new TestCase(name) {
      @Override
      public void runTest() {
        CookieStore store = GCookie.makeStore();
        GCookie.parseResponseHeaders(headers, responseUri, store);
        for (GCookie cookie : store) {
          logger.info(name + " parsed cookie: " + cookie.responseHeaderString(true));
        }
        Set<GCookie> sent = Sets.newHashSet();
        for (GCookie cookie : store) {
          if (cookie.isGoodFor(requestUri)) {
            sent.add(GCookie.make(cookie.getName(), cookie.getValue()));
          }
        }
        Set<GCookie> overridden = overrideExpected(name, expected);
        assertEquals(overridden, sent);
      }
    };
  }

  private static Set<GCookie> overrideExpected(String name, Set<GCookie> expected) {
    if ("DOMAIN0017".equals(name)) {
      // We don't support public suffixes yet.
      return ImmutableSet.of(GCookie.make("foo", "bar"));
    }
    if ("DISABLED_CHROMIUM0022".equals(name)) {
      return ImmutableSet.of(GCookie.make("AAA", "BB\u0000ZYX"));
    }
    if ("DISABLED_CHROMIUM0023".equals(name)) {
      return ImmutableSet.of(GCookie.make("AAA", "BB\rZYX"));
    }
    return expected;
  }
}
