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

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.enterprise.secmgr.matcher.SucceedResult;
import com.google.enterprise.secmgr.testing.EqualValueExpectation;
import com.google.enterprise.secmgr.testing.Expectation;
import com.google.enterprise.secmgr.testing.FunctionTest;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.enterprise.secmgr.testing.SimpleExceptionExpectation;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import junit.framework.TestCase;

/**
 * Tests for the {@link HttpUtil} class.
 */
public final class HttpUtilTest extends TestCase {

  private static final String FOO = "foo";
  private static final String BAR = "bar";
  private static final String SEPARATOR_CHARS = "()<>@,;:\\\"/[]?={} \t";
  private static final String TOKEN_CHARS = computeTokenChars();

  private static String computeTokenChars() {
    StringBuilder builder = new StringBuilder();
    for (int i = 0x20; i < 0x7f; i += 1) {
      char c = (char) i;
      if (SEPARATOR_CHARS.indexOf(c) < 0) {
        builder.append(c);
      }
    }
    return builder.toString();
  }

  /**
   * Test the {@link HttpUtil#isHttpToken} method.
   */
  public void testIsHttpToken() {
    SecurityManagerTestCase.runTests(TOKEN_TESTS);
  }

  private static final Iterable<TokenTest> TOKEN_TESTS = makeIsHttpTokenTests();

  private static Iterable<TokenTest> makeIsHttpTokenTests() {
    ImmutableList.Builder<TokenTest> builder = ImmutableList.builder();

    TokenTest.make(FOO, true, builder);
    TokenTest.make(BAR, true, builder);
    TokenTest.make("", false, builder);

    for (int i = 0; i < 0x100; i += 1) {
      char c = (char) i;
      TokenTest.make(
          makeCombos(String.valueOf(c)),
          TOKEN_CHARS.indexOf(c) >= 0,
          builder);
    }

    return builder.build();
  }

  private static class TokenTest extends FunctionTest<String, Boolean> {

    public static void make(String input, boolean expectedValue,
        ImmutableList.Builder<TokenTest> builder) {
      builder.add(new TokenTest(input, expectedValue));
    }

    public static void make(Iterable<String> inputs, boolean expectedValue,
        ImmutableList.Builder<TokenTest> builder) {
      for (String input : inputs) {
        make(input, expectedValue, builder);
      }
    }

    private TokenTest(String input, Boolean expectedValue) {
      super(IS_HTTP_TOKEN, input, EqualValueExpectation.make(expectedValue));
    }

    private static final Function<String, Boolean> IS_HTTP_TOKEN =
        new Function<String, Boolean>() {
          public Boolean apply(String input) {
            return HttpUtil.isHttpToken(input);
          }
        };

    public boolean getExpectedValue() {
      return (Boolean) EqualValueExpectation.class.cast(getExpectation()).getExpectedValue();
    }
  }

  /**
   * Test the {@link HttpUtil#parseHttpQuotedString} method.
   */
  public void testParseHttpQuotedString() {
    SecurityManagerTestCase.runTests(QUOTED_STRING_TESTS);
  }

  private static final Iterable<QuotedStringTest> QUOTED_STRING_TESTS =
      makeParseHttpQuotedStringTests();

  private static Iterable<QuotedStringTest> makeParseHttpQuotedStringTests() {
    ImmutableList.Builder<QuotedStringTest> builder = ImmutableList.builder();

    QuotedStringTest.makeGood("", builder);
    QuotedStringTest.makeGood(FOO, builder);
    QuotedStringTest.makeGood(BAR, builder);

    QuotedStringTest.makeBad("", builder);

    QuotedStringTest.makeBad(makeCombos("\""), builder);
    QuotedStringTest.makeBad(wrapQuotes(makeCombos("\"")), builder);

    QuotedStringTest.makeBad(makeCombos("\\"), builder);
    QuotedStringTest.makeBad(wrapQuotes("\\"), builder);
    QuotedStringTest.makeGood("\\" + BAR, BAR, builder);
    QuotedStringTest.makeBad(FOO + "\\", builder);
    QuotedStringTest.makeGood(FOO + "\\" + BAR, FOO + BAR, builder);

    QuotedStringTest.makeGood(makeCombos(" "), builder);
    QuotedStringTest.makeBad(makeCombos(" "), builder);

    return builder.build();
  }

  private static final class QuotedStringTest extends FunctionTest<String, String> {

    public static void makeGood(String input, String expectedValue,
        ImmutableList.Builder<QuotedStringTest> builder) {
      Expectation<String> expectation = EqualValueExpectation.make(expectedValue);
      builder.add(new QuotedStringTest(wrapQuotes(input), expectation));
    }

    public static void makeGood(String input, ImmutableList.Builder<QuotedStringTest> builder) {
      makeGood(input, input, builder);
    }

    public static void makeGood(Iterable<String> inputs,
        ImmutableList.Builder<QuotedStringTest> builder) {
      for (String input : inputs) {
        makeGood(input, input, builder);
      }
    }

    public static void makeBad(String input, ImmutableList.Builder<QuotedStringTest> builder) {
      Expectation<String> expectation
          = SimpleExceptionExpectation.make(IllegalArgumentException.class);
      builder.add(new QuotedStringTest(input, expectation));
    }

    public static void makeBad(Iterable<String> inputs,
        ImmutableList.Builder<QuotedStringTest> builder) {
      for (String input : inputs) {
        makeBad(input, builder);
      }
    }

    private QuotedStringTest(String input, Expectation<String> expectation) {
      super(PARSE_QUOTED_STRING, input, expectation);
    }

    private static final Function<String, String> PARSE_QUOTED_STRING =
        new Function<String, String>() {
          public String apply(String input) {
            return HttpUtil.parseHttpQuotedString(input);
          }
        };

    public boolean expectsValue() {
      return expectation instanceof EqualValueExpectation<?>;
    }

    public String getExpectedValue() {
      return ((EqualValueExpectation<String>) expectation).getExpectedValue();
    }
  }

  /**
   * Test the {@link HttpUtil#parseHttpParameter} method.
   */
  public void testParseHttpParameter() {
    SecurityManagerTestCase.runTests(PARAMETER_TESTS);
  }

  private static final Iterable<ParameterTest> PARAMETER_TESTS = makeParameterTests();

  private static Iterable<ParameterTest> makeParameterTests() {
    ImmutableList.Builder<ParameterTest> builder = ImmutableList.builder();

    ParameterTest.makeBad("", builder);

    for (TokenTest nameTest : TOKEN_TESTS) {
      if (nameTest.getExpectedValue()) {
        ParameterTest.makeBad(nameTest.getInput(), builder);
      }
      for (TokenTest valueTest : TOKEN_TESTS) {
        if (nameTest.getExpectedValue() && valueTest.getExpectedValue()) {
          ParameterTest.makeGood(
              nameTest.getInput() + "=" + valueTest.getInput(),
              ImmutableList.of(nameTest.getInput(), valueTest.getInput()),
              builder);
        } else {
          ParameterTest.makeBad(
              nameTest.getInput() + "=" + valueTest.getInput(),
              builder);
        }
      }
      for (QuotedStringTest valueTest : QUOTED_STRING_TESTS) {
        if (nameTest.getExpectedValue() && valueTest.expectsValue()) {
          ParameterTest.makeGood(
              nameTest.getInput() + "=" + valueTest.getInput(),
              ImmutableList.of(nameTest.getInput(), valueTest.getExpectedValue()),
              builder);
        } else {
          ParameterTest.makeBad(
              nameTest.getInput() + "=" + valueTest.getInput(),
              builder);
        }
      }
    }

    return builder.build();
  }

  private static final class ParameterTest extends FunctionTest<String, List<String>> {

    public static void makeGood(String input, List<String> expectedValue,
        ImmutableList.Builder<ParameterTest> builder) {
      Expectation<List<String>> expectation = EqualValueExpectation.make(expectedValue);
      builder.add(new ParameterTest(input, expectation));
    }

    public static void makeBad(String input, ImmutableList.Builder<ParameterTest> builder) {
      Expectation<List<String>> expectation
          = SimpleExceptionExpectation.make(IllegalArgumentException.class);
      builder.add(new ParameterTest(input, expectation));
    }

    private ParameterTest(String input, Expectation<List<String>> expectation) {
      super(PARSE_HTTP_PARAMETER, input, expectation);
    }

    private static final Function<String, List<String>> PARSE_HTTP_PARAMETER =
        new Function<String, List<String>>() {
          public List<String> apply(String input) {
            return HttpUtil.parseHttpParameter(input);
          }
        };
  }

  private static Iterable<String> makeCombos(String s) {
    return makeCombos(s, FOO, BAR);
  }

  private static Iterable<String> makeCombos(String s, String a, String b) {
    return ImmutableList.of(s, a + s, s + b, a + s + b);
  }

  private static String wrapQuotes(String s) {
    return "\"" + s + "\"";
  }

  private static Iterable<String> wrapQuotes(Iterable<String> strings) {
    return Iterables.transform(strings,
        new Function<String, String>() {
          public String apply(String s) {
            return wrapQuotes(s);
          }
        });
  }

  public void testPostFormMatcher() {
    tryPostFormMatcher("uDefault", "foobar");
    tryPostFormMatcher("uDefault", "foobar", "pwDefault", "foobaz");
    tryPostFormMatcher("uDefault", "%E6%BC%A2%E5%AD%97");
    tryPostFormMatcher("uDefault", "%E6%BC%A2%E5%AD%97foobar");
    tryPostFormMatcher("uDefault", "%E6%BC%A2%E5%AD%97", "pwDefault", "foobar");
    tryPostFormMatcher("uDefault", "spuser1", "pwDefault", "Test%21@%23");  // b/5458197
  }

  private void tryPostFormMatcher(String... values) {
    String testString = makeTestString(values);
    SucceedResult result = HttpUtil.POST_FORM_MATCHER.topLevelMatch(testString);
    assertNotNull("Failed to match: " + Stringify.object(testString), result);
    assertEquals(makeExpectedResult(values), result.getState().getStack().toList());
  }

  private String makeTestString(String... values) {
    StringBuilder builder = new StringBuilder();
    for (int i = 0; i < values.length; i += 2) {
      if (i > 0) {
        builder.append('&');
      }
      builder.append(values[i]);
      builder.append('=');
      builder.append(values[i + 1]);
    }
    return builder.toString();
  }

  private List<Object> makeExpectedResult(String... values) {
    return ImmutableList.<Object>copyOf(values);
  }

  public void testParsingDomainMiddleUnderscoresPermitted() {
    String example = "nashi_1_2.tok.corp.google.com";
    HttpUtil.canonicalizeDomainName(example);
  }

  public void testParsingDomainStartUnderscoreRejected() {
    String example = "_nashi_1.tok.corp.google.com";
    try {
      HttpUtil.canonicalizeDomainName(example);
      fail("not allowed to have underscore at beginning of domain");
    } catch (IllegalArgumentException expected) {
    }
  }

  public void testParsingDomainEndUnderscoreRejected() {
    String example = "nashi_1_.tok.corp.google.com";
    try {
      HttpUtil.canonicalizeDomainName(example);
      fail("not allowed to have underscore at end of domain");
    } catch (IllegalArgumentException expected) {
    }
  }

  public void testParsingDomainStartUnderscoreRejected2() {
    String example = "nashi1.tok._corp.google.com";
    try {
      HttpUtil.canonicalizeDomainName(example);
      fail("not allowed to have underscore at beginning of domain");
    } catch (IllegalArgumentException expected) {
    }
  }

  public void testParsingDomainEndUnderscoreRejected2() {
    String example = "nashi1.tok.corp_.google.com";
    try {
      HttpUtil.canonicalizeDomainName(example);
      fail("not allowed to have underscore at end of domain");
    } catch (IllegalArgumentException expected) {
    }
  }

  public void testToUriBracketsInUrlConverted() {
    String example = "http://nashi1.tok:8074/_[_LAITO_]_.html";
    try {
      URI result = HttpUtil.toUri(new URL(example));
      assertEquals("nashi1.tok", result.getHost());
      String golden = "http://nashi1.tok:8074/_%5B_LAITO_%5D_.html";
      assertEquals(golden, "" + result);
    } catch (MalformedURLException mue) {
      fail("couldn't make URL object from " + example);
    }
  }

  public void testToUriBracketsInIpv6Preserved() {
    String example = "http://[1fff:0:a88:85a3::ac1f]:8001/index.html";
    try {
      URI result = HttpUtil.toUri(new URL(example));
      assertEquals("[1fff:0:a88:85a3::ac1f]", result.getHost());
      assertEquals(example, "" + result);
    } catch (MalformedURLException mue) {
      fail("couldn't make URL object from " + example);
    }
  }

  public void testToUriAllPartsPreserved() {
    String example = "ftp://username:password@host:8080/p/p/d?query#fragment";
    try {
      URI result = HttpUtil.toUri(new URL(example));
      assertEquals(example, "" + result);
    } catch (MalformedURLException mue) {
      fail("couldn't make URL object from " + example);
    }
  }

  public void testToUriMultipleBracketsInUrlConverted() {
    String example = "http://nashi1.tok:8074/_[_L[AI][TO_]]_.html";
    try {
      URI result = HttpUtil.toUri(new URL(example));
      String golden = "http://nashi1.tok:8074/_%5B_L%5BAI%5D%5BTO_%5D%5D_.html";
      assertEquals(golden, "" + result);
    } catch (MalformedURLException mue) {
      fail("couldn't make URL object from " + example);
    }
  }

  public void testBracketUrlCodeValues() {
    assertEquals("_[_L[AI][TO_]]_.html", java.net.URLDecoder.decode(
        "_%5B_L%5BAI%5D%5BTO_%5D%5D_.html"));
  }

  public void testToUriWhenHostHasUnderscore() {
    String example = "http://debasis_rath.hyd.corp.google.com/private";
    try {
      URI result = HttpUtil.toUri(new URL(example));
      assertEquals("debasis_rath.hyd.corp.google.com", result.getHost());
    } catch (MalformedURLException mue) {
      fail("couldn't make URL object from " + example);
    }
  }

  public void testToUriWhenHostHasUnderscoreAndUrlHasAllParts() {
    String example = "ftp://johnny:t3St@ab_cd_ef.com:1337/dir/file?quer#frag";
    try {
      URI result = HttpUtil.toUri(new URL(example));
      assertEquals(example, "" + result);
      assertEquals("ftp", result.getScheme());
      assertEquals("johnny:t3St", result.getUserInfo());
      assertEquals("ab_cd_ef.com", result.getHost());
      assertEquals(1337, result.getPort());
      assertEquals("/dir/file", result.getPath());
      assertEquals("quer", result.getQuery());
      assertEquals("frag", result.getFragment());
      assertEquals("johnny:t3St@ab_cd_ef.com:1337", result.getAuthority());
    } catch (MalformedURLException mue) {
      fail("couldn't make URL object from " + example);
    }
  }

  public void testToUriWhenHostHasUnderscoreAndUrlHasAllPartsButQueryAndFrag() {
    String example = "https://johnny:t3St@ab_cd_ef.com:1337/dir/more/fff";
    try {
      URI result = HttpUtil.toUri(new URL(example));
      assertEquals(example, "" + result);
      assertEquals("https", result.getScheme());
      assertEquals("johnny:t3St", result.getUserInfo());
      assertEquals("ab_cd_ef.com", result.getHost());
      assertEquals(1337, result.getPort());
      assertEquals("/dir/more/fff", result.getPath());
      assertEquals(null, result.getQuery());
      assertEquals(null, result.getFragment());
      assertEquals("johnny:t3St@ab_cd_ef.com:1337", result.getAuthority());
    } catch (MalformedURLException mue) {
      fail("couldn't make URL object from " + example);
    }
  }

  public void testUnderscoreUriEquals() throws MalformedURLException {
    URL example = new URL("https://johnny:t3St@abcd.com:1337/dir/more/fff");
    URI normallyMade = HttpUtil.toUri(example);
    URI underscoreMade = HttpUtil.makeUriWithUnderscoreInHostname(example);
    assertEquals(normallyMade, underscoreMade);
    assertTrue(0 == normallyMade.compareTo(underscoreMade));
  }

  public void testUnderscoreUriEquals2() throws MalformedURLException,
      URISyntaxException {
    URL example = new URL("ftp://johnny:t3St@ab.au:1337/dir/file?q=v&a=b#frag");
    URI normallyMade = HttpUtil.toUri(example);
    URI underscoreMade = HttpUtil.makeUriWithUnderscoreInHostname(example);
    assertEquals(normallyMade, underscoreMade);
    assertTrue(0 == normallyMade.compareTo(underscoreMade));
    assertEquals(normallyMade.getRawAuthority(), underscoreMade.getRawAuthority());
    assertEquals(normallyMade.getRawFragment(), underscoreMade.getRawFragment());
    assertEquals(normallyMade.getRawPath(), underscoreMade.getRawPath());
    assertEquals(normallyMade.getRawQuery(), underscoreMade.getRawQuery());
    assertEquals(normallyMade.getRawSchemeSpecificPart(),
        underscoreMade.getRawSchemeSpecificPart());
    assertEquals(normallyMade.getRawUserInfo(), underscoreMade.getRawUserInfo());
    assertEquals(normallyMade.hashCode(), underscoreMade.hashCode());
    assertEquals(normallyMade.isAbsolute(), underscoreMade.isAbsolute());
    assertEquals(normallyMade.isOpaque(), underscoreMade.isOpaque());
    assertEquals(normallyMade.normalize(), underscoreMade.normalize());
    assertEquals(normallyMade.parseServerAuthority(),
        underscoreMade.parseServerAuthority());
    assertEquals(normallyMade.toASCIIString(), underscoreMade.toASCIIString());
    assertEquals(normallyMade.toURL(), underscoreMade.toURL());

    assertEquals("ftp://johnny:t3St@ab.au:1337/dir/file?q=v&a=b#frag", "" + underscoreMade);
    assertEquals("johnny:t3St@ab.au:1337", underscoreMade.getRawAuthority());
    assertEquals("frag", underscoreMade.getRawFragment());
    assertEquals("/dir/file", underscoreMade.getRawPath());
    assertEquals("q=v&a=b", underscoreMade.getRawQuery());
    assertEquals("//johnny:t3St@ab.au:1337/dir/file?q=v&a=b",
        underscoreMade.getRawSchemeSpecificPart());
    assertEquals("johnny:t3St", underscoreMade.getRawUserInfo());
    assertEquals(true, underscoreMade.isAbsolute());
    assertEquals(false, underscoreMade.isOpaque());
    assertEquals("ftp://johnny:t3St@ab.au:1337/dir/file?q=v&a=b#frag",
        "" + underscoreMade.parseServerAuthority());
    assertEquals("ftp://johnny:t3St@ab.au:1337/dir/file?q=v&a=b#frag",
        underscoreMade.toASCIIString());
    assertEquals("ftp://johnny:t3St@ab.au:1337/dir/file?q=v&a=b#frag",
        "" + underscoreMade.toURL());
  }
}
