// Copyright 2011 Google Inc.
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

package com.google.enterprise.secmgr.matcher;

import static com.google.enterprise.secmgr.matcher.Matcher.alternatives;
import static com.google.enterprise.secmgr.matcher.Matcher.anyChar;
import static com.google.enterprise.secmgr.matcher.Matcher.atEnd;
import static com.google.enterprise.secmgr.matcher.Matcher.atStart;
import static com.google.enterprise.secmgr.matcher.Matcher.continueTopLevelMatch;
import static com.google.enterprise.secmgr.matcher.Matcher.getMatcher;
import static com.google.enterprise.secmgr.matcher.Matcher.literal;
import static com.google.enterprise.secmgr.matcher.Matcher.oneOf;
import static com.google.enterprise.secmgr.matcher.Matcher.sequence;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import junit.framework.TestCase;

/**
 * Unit tests of the top-level matcher.
 *
 */
public final class MatcherTest extends TestCase {
  private static final Logger LOGGER = Logger.getLogger(MatcherTest.class.getName());

  public void testAnyChar() {
    LOGGER.info("start test: testAnyChar");
    Matcher m = anyChar();
    failTest(m, "");
    simpleTest(m, "a");
    simpleTest(m, "b");
    simpleTest(m, "\n");
  }

  public void testAnyCharStar() {
    LOGGER.info("start test: testAnyCharStar");
    Matcher m = anyChar().star();
    assertLength(0).run(m, "");
    simpleTest(m, "a");
    simpleTest(m, "ab");
    simpleTest(m, "abc");
    simpleTest(m, "ab\n");
    simpleTest(m, "a\nb");
  }

  public void testSimpleSequence() {
    LOGGER.info("start test: testSimpleSequence");
    Matcher m = sequence(literal("a"), literal("b"));
    failTest(m, "");
    failTest(m, "a");
    simpleTest(m, "ab");
    assertLength(2).run(m, "abc");
  }

  public void testRepeatEquivalences() {
    LOGGER.info("start test: testRepeatEquivalences");
    List<String> testStrings = ImmutableList.of("", "a", "b", "ab", "ba", "aab");
    Matcher m0 = literal("");
    Matcher ma = literal("a");
    Matcher maa = literal("aa");
    tryEquivalents(
        ImmutableList.of(
            m0,
            ma.repeat(0, 0),
            ma.repeat(0),
            ma.lazyRepeat(0, 0),
            ma.lazyRepeat(0),
            sequence(m0, m0)),
        testStrings,
        assertLengths(0, 0, 0, 0, 0, 0));
    tryEquivalents(
        ImmutableList.of(
            ma,
            ma.repeat(1, 1),
            ma.repeat(1),
            ma.lazyRepeat(1, 1),
            ma.lazyRepeat(1),
            sequence(ma, m0),
            sequence(m0, ma)),
        testStrings,
        assertLengths(-1, 1, -1, 1, -1, 1));
    tryEquivalents(
        ImmutableList.of(
            maa,
            ma.repeat(2, 2),
            ma.repeat(2),
            ma.lazyRepeat(2, 2),
            ma.lazyRepeat(2),
            sequence(ma, ma),
            sequence(maa, m0),
            sequence(m0, maa)),
        testStrings,
        assertLengths(-1, -1, -1, -1, -1, 2));
    tryEquivalents(
        ImmutableList.of(
            ma.star(),
            ma.repeat(0, Integer.MAX_VALUE)),
        testStrings,
        assertLengths(0, 1, 0, 1, 0, 2));
    tryEquivalents(
        ImmutableList.of(
            ma.lazyStar(),
            ma.lazyRepeat(0, Integer.MAX_VALUE)),
        testStrings,
        assertLengths(0, 0, 0, 0, 0, 0));
    tryEquivalents(
        ImmutableList.of(
            ma.plus(),
            sequence(ma, ma.star()),
            ma.repeat(1, Integer.MAX_VALUE)),
        testStrings,
        assertLengths(-1, 1, -1, 1, -1, 2));
    tryEquivalents(
        ImmutableList.of(
            ma.lazyPlus(),
            sequence(ma, ma.lazyStar()),
            ma.lazyRepeat(1, Integer.MAX_VALUE)),
        testStrings,
        assertLengths(-1, 1, -1, 1, -1, 1));
    tryEquivalents(
        ImmutableList.of(
            ma.optional(),
            ma.repeat(0, 1)),
        testStrings,
        assertLengths(0, 1, 0, 1, 0, 1));
    tryEquivalents(
        ImmutableList.of(
            ma.lazyOptional(),
            ma.lazyRepeat(0, 1)),
        testStrings,
        assertLengths(0, 0, 0, 0, 0, 0));
  }

  private void tryEquivalents(List<Matcher> matchers, List<String> strings,
      Runner<List<SucceedResult>> assertions) {
    for (Matcher m : matchers) {
      assertions.run(runMatches(m, strings));
    }
  }

  public void testRepeat() {
    LOGGER.info("start test: testRepeat");
    Matcher ma = literal("a");
    Matcher mb = literal("b");
    Matcher mab = literal("ab");
    Matcher maab = literal("aab");

    Matcher mago = ma.optional();
    assertLengths(2, 1).run(runAllMatches(sequence(mago, ma), "aab"));
    assertLengths(3).run(runAllMatches(sequence(mago, mab), "aab"));

    Matcher malo = ma.lazyOptional();
    assertLengths(1, 2).run(runAllMatches(sequence(malo, ma), "aab"));
    assertLengths(3).run(runAllMatches(sequence(malo, mab), "aab"));

    Matcher mag12 = ma.repeat(1, 2);
    assertLengths(2, 1).run(runAllMatches(mag12, "aab"));
    assertLengths(3).run(runAllMatches(sequence(mag12, mb), "aab"));

    Matcher mal12 = ma.lazyRepeat(1, 2);
    assertLengths(1, 2).run(runAllMatches(mal12, "aab"));
    assertLengths(3).run(runAllMatches(sequence(mal12, mb), "aab"));

    Matcher mag13 = ma.repeat(1, 3);
    assertLengths(3, 2, 1).run(runAllMatches(mag13, "aaab"));
    assertLengths(4).run(runAllMatches(sequence(mag13, mb), "aaab"));

    Matcher mal13 = ma.lazyRepeat(1, 3);
    assertLengths(1, 2, 3).run(runAllMatches(mal13, "aaab"));
    assertLengths(4).run(runAllMatches(sequence(mal13, mb), "aaab"));

    Matcher magop = mago.pushMatchedString();
    assertLength(2).and(assertStack("a")).run(sequence(magop, ma), "aab");
    assertLength(3).and(assertStack("a")).run(sequence(magop, mab), "aab");
    assertLength(3).and(assertStack("")).run(sequence(magop, maab), "aab");

    Matcher malop = malo.pushMatchedString();
    assertLength(1).and(assertStack("")).run(sequence(malop, ma), "aab");
    assertLength(3).and(assertStack("a")).run(sequence(malop, mab), "aab");
    assertLength(3).and(assertStack("")).run(sequence(malop, maab), "aab");

    Matcher magsp = ma.star().pushMatchedString();
    assertLength(3).and(assertStack("aa")).run(sequence(magsp, mb), "aab");
    assertLength(3).and(assertStack("a")).run(sequence(magsp, mab), "aab");
    assertLength(3).and(assertStack("")).run(sequence(magsp, maab), "aab");

    Matcher malsp = ma.lazyStar().pushMatchedString();
    assertLength(3).and(assertStack("aa")).run(sequence(malsp, mb), "aab");
    assertLength(3).and(assertStack("a")).run(sequence(malsp, mab), "aab");
    assertLength(3).and(assertStack("")).run(sequence(malsp, maab), "aab");
  }

  public void testPalindromes() {
    LOGGER.info("start test: testPalindromes");
    Matcher p1 = sequence(
        atStart(),
        anyChar().putMatchedString("A"),
        anyChar().putMatchedString("B"),
        anyChar(),
        getMatcher("B"),
        getMatcher("A"),
        atEnd());
    assertDicts(ImmutableList.of(ImmutableMap.<Object, Object>of("A", "r", "B", "a")))
        .run(runAllMatches(p1, "radar"));

    Matcher p2 = makePalindrome(anyChar().optional());
    tryPalindrome(true, p2, "aa");
    tryPalindrome(true, p2, "ava");
    tryPalindrome(true, p2, "civic");
    tryPalindrome(true, p2, "abba");

    Matcher p3 = makePalindrome(anyChar().lazyOptional());
    tryPalindrome(false, p3, "aa");
    tryPalindrome(false, p3, "ava");
    tryPalindrome(false, p3, "civic");
    tryPalindrome(false, p3, "abba");
  }

  private Matcher makePalindrome(Matcher m) {
    return sequence(
        atStart(),
        m.putMatchedString(1),
        m.putMatchedString(2),
        m.putMatchedString(3),
        m.putMatchedString(4),
        m.putMatchedString(5),
        m.putMatchedString(6),
        m.putMatchedString(7),
        m.putMatchedString(8),
        m.putMatchedString(9),
        m,
        getMatcher(9),
        getMatcher(8),
        getMatcher(7),
        getMatcher(6),
        getMatcher(5),
        getMatcher(4),
        getMatcher(3),
        getMatcher(2),
        getMatcher(1),
        atEnd());
  }

  private void tryPalindrome(boolean isGreedy, Matcher m, String string) {
    palindromeAssertions(isGreedy, string).run(runAllMatches(m, string));
  }

  private Runner<List<SucceedResult>> palindromeAssertions(boolean isGreedy,
      String string) {
    int n = string.length() / 2;
    String[] strings = new String[n];
    for (int i = 0; i < n; i += 1) {
      strings[i] = string.substring(i, i + 1);
    }
    List<ResultAssertion> assertions = Lists.newArrayList();
    List<int[]> expectations = generatePalindromeIndices(1, n);
    for (int[] indices : isGreedy ? expectations : Lists.reverse(expectations)) {
      Map<Object, Object> expected = Maps.newHashMap();
      for (int i = 1; i <= 9; i += 1) {
        String s = "";
        for (int j = 0; j < n; j += 1) {
          if (i == indices[j]) {
            s = strings[j];
          }
        }
        expected.put(i, s);
      }
      assertions.add(assertDict(expected));
    }
    return mapAssertions(assertions);
  }

  private List<int[]> generatePalindromeIndices(int start, int n) {
    List<int[]> result = Lists.newArrayList();
    for (int i = start; i <= 10 - n; i += 1) {
      if (n > 1) {
        for (int[] indices : generatePalindromeIndices(i + 1, n - 1)) {
          int[] indices2 = new int[n];
          indices2[0] = i;
          for (int j = 1; j < n; j += 1) {
            indices2[j] = indices[j - 1];
          }
          result.add(indices2);
        }
      } else {
        result.add(new int[] { i });
      }
    }
    return result;
  }

  // Ripped off from "grep/tests/bre.tests".
  public void testBasic() {
    LOGGER.info("start test: testBasic");
    Matcher m;
    simpleTest(
        sequence(
            literal("a"),
            sequence(literal("b")),
            literal("c")),
        "abc");
    simpleTest(
        sequence(
            literal("a"),
            sequence(),
            literal("b")),
        "ab");
    failTest(
        sequence(
            atStart(),
            anyChar().putMatchedString("x"),
            getMatcher("x")),
        "abc");
    assertLength(5).and(assertDict("x", "a"))
        .run(
            sequence(
                literal("a").putMatchedString("x"),
                getMatcher("x"),
                literal("bcd")),
            "aabcd");
    basicRepeats(GREEDY_REPEATER);
    basicRepeats(LAZY_REPEATER);
  }

  private void basicRepeats(Repeater r) {
    Matcher m;
    simpleTest(
        sequence(
            r.star(literal("a")),
            sequence(
                atStart(),
                literal("b"),
                atEnd()),
            r.star(literal("c"))),
        "b");
    assertLength(0).run(sequence(), "abc");
    m = sequence(
        literal("a"),
        r.star(literal("b")).putMatchedString("x"),
        literal("c"),
        getMatcher("x"),
        literal("d"));
    failTest(m, "abbcbd");
    assertLength(7).and(assertDict("x", "bb")).run(m, "abbcbbd");
    failTest(m, "abbcbbbd");
    m = sequence(
        literal("a"),
        r.star(
            sequence(
                oneOf("bc").putMatchedString("x"),
                getMatcher("x"))),
        literal("d"));
    assertLength(6).and(assertDict("x", "c")).run(m, "abbccd");
    failTest(m, "abbcbd");
    assertLength(5).and(assertDict("x", "b"))
        .run(
            sequence(
                literal("a"),
                r.star(
                    sequence(
                        r.star(literal("b").putMatchedString("x")),
                        getMatcher("x"))),
                literal("d")),
            "abbbd");
    m = sequence(
        literal("a").putMatchedString("x"),
        getMatcher("x"),
        literal("b"),
        r.star(literal("c")),
        literal("d"));
    assertLength(5).and(assertDict("x", "a")).run(m, "aabcd");
    assertLength(4).and(assertDict("x", "a")).run(m, "aabd");
    assertLength(7).and(assertDict("x", "a")).run(m, "aabcccd");
    assertLength(7).and(assertDict("x", "a")).run(
        sequence(
            literal("a").putMatchedString("x"),
            getMatcher("x"),
            literal("b"),
            r.star(literal("c")),
            oneOf("ce"),
            literal("d")),
        "aabcccd");
    assertLength(7).and(assertDict("x", "a")).run(
        sequence(
            atStart(),
            literal("a").putMatchedString("x"),
            getMatcher("x"),
            literal("b"),
            r.star(literal("c")),
            oneOf("cd"),
            atEnd()),
        "aabcccd");
    simpleTest(
        sequence(
            r.repeat(literal("a"), 1),
            literal("b")),
        "ab");
    simpleTest(
        sequence(
            r.repeat(literal("a"), 1, Integer.MAX_VALUE),
            literal("b")),
        "ab");
    simpleTest(
        sequence(
            r.repeat(literal("a"), 1, 2),
            literal("b")),
        "aab");
    m = sequence(
        literal("a"),
        r.repeat(literal("b"), 0),
        literal("c"));
    simpleTest(m, "ac");
    failTest(m, "abc");
    m = sequence(
        literal("a"),
        r.repeat(literal("b"), 0, 1),
        literal("c"));
    simpleTest(m, "ac");
    simpleTest(m, "abc");
    failTest(m, "abbc");
    m = sequence(
        literal("a"),
        r.repeat(literal("b"), 0, 3),
        literal("c"));
    simpleTest(m, "ac");
    simpleTest(m, "abc");
    simpleTest(m, "abbc");
    simpleTest(m, "abbbc");
    failTest(m, "abbbbc");
    m = sequence(
        literal("a"),
        r.repeat(literal("b"), 1),
        literal("c"));
    failTest(m, "ac");
    simpleTest(m, "abc");
    m = sequence(
        literal("a"),
        r.repeat(literal("b"), 2),
        literal("c"));
    failTest(m, "abc");
    simpleTest(m, "abbc");
    m = sequence(
        literal("a"),
        r.repeat(literal("b"), 2, 4),
        literal("c"));
    failTest(m, "abcabbc");
    simpleTest(
        sequence(
            literal("a"),
            r.optional(literal("b")).putMatchedString("x"),
            literal("c"),
            getMatcher("x"),
            literal("d")),
        "acd");
    simpleTest(
        sequence(
            atStart(),
            r.optional(literal("-")),
            oneOf("0123456789"),
            atEnd()),
        "-5");
  }

  // Ripped off from "grep/tests/ere.tests".
  public void testExtended() {
    LOGGER.info("start test: testExtended");
    Matcher m;
    simpleTest(
        alternatives(
            literal("abc"),
            literal("de")),
        "abc");
    assertLength(1).run(
        alternatives(
            literal("a"),
            literal("b"),
            literal("c")),
        "abc");
    simpleTest(
        sequence(
            literal("a"),
            anyChar(),
            literal("c")),
        "abc");
    simpleTest(
        sequence(
            literal("a"),
            oneOf("bc"),
            literal("d")),
        "abd");
    simpleTest(
        sequence(
            literal("a"),
            oneOf("b"),
            literal("c")),
        "abc");
    simpleTest(
        sequence(
            literal("a"),
            oneOf("ab"),
            literal("c")),
        "abc");
    m = sequence(
        literal("a"),
        oneOf(CharSet.make("ab").invert()),
        literal("c"));
    failTest(m, "abc");
    simpleTest(m, "adc");
    m = sequence(
        literal("a"),
        oneOf("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        literal("c"));
    simpleTest(m, "abc");
    simpleTest(m, "adc");
    m = sequence(
        literal("a"),
        oneOf("ab"), oneOf("ab"), oneOf("ab"), oneOf("ab"),
        oneOf("ab"), oneOf("ab"), oneOf("ab"), oneOf("ab"),
        oneOf("ab"), oneOf("ab"), oneOf("ab"), oneOf("ab"),
        oneOf("ab"), oneOf("ab"), oneOf("ab"), oneOf("ab"),
        oneOf("ab"), oneOf("ab"), oneOf("ab"), oneOf("ab"));
    simpleTest(m, "aaaaabaaaabaaaabaaaab");
    m = sequence(
        literal("a"),
        oneOf("ab"), oneOf("ab"), oneOf("ab"), oneOf("ab"),
        oneOf("ab"), oneOf("ab"), oneOf("ab"), oneOf("ab"),
        oneOf("ab"), oneOf("ab"), oneOf("ab"), oneOf("ab"),
        oneOf("ab"), oneOf("ab"), oneOf("ab"), oneOf("ab"),
        oneOf("ab"), oneOf("ab"), oneOf("ab"), oneOf("ab"),
        alternatives(literal("wee"), literal("week")),
        alternatives(literal("knights"), literal("night")));
    simpleTest(m, "aaaaabaaaabaaaabaaaabweeknights");
    m = sequence(
        oneOf("ab"), oneOf("cd"), oneOf("ef"), oneOf("gh"),
        oneOf("ij"), oneOf("kl"), oneOf("mn"));
    assertLength(7).run(m, "acegikmoq");
    m = sequence(
        oneOf("ab"), oneOf("cd"), oneOf("ef"), oneOf("gh"),
        oneOf("ij"), oneOf("kl"), oneOf("mn"), oneOf("op"));
    assertLength(8).run(m, "acegikmoq");
    m = sequence(
        oneOf("ab"), oneOf("cd"), oneOf("ef"), oneOf("gh"),
        oneOf("ij"), oneOf("kl"), oneOf("mn"), oneOf("op"),
        oneOf("qr"));
    simpleTest(m, "acegikmoq");
    assertLength(9).run(m, "acegikmoqy");
    m = sequence(
        oneOf("ab"), oneOf("cd"), oneOf("ef"), oneOf("gh"),
        oneOf("ij"), oneOf("kl"), oneOf("mn"), oneOf("op"),
        oneOf("q"));
    assertLength(9).run(m, "acegikmoqy");
    failTest(literal("aBc"), "Abc");
    m = sequence(
        literal("a"),
        oneOf(CharSet.make("b").invert()),
        literal("c"));
    failTest(m, "abc");
    simpleTest(m, "aBc");
    simpleTest(m, "adc");
    m = sequence(
        oneOf("a"),
        literal("b"),
        oneOf("c"));
    simpleTest(m, "abc");
    m = sequence(
        oneOf("a"),
        literal("b"),
        oneOf("a"));
    simpleTest(m, "aba");
    m = sequence(
        oneOf("abc"),
        literal("b"),
        oneOf("abc"));
    simpleTest(m, "abc");
    m = sequence(
        oneOf("abc"),
        literal("b"),
        oneOf("abd"));
    failTest(m, "abc");
    simpleTest(m, "abd");
    m = sequence(
        alternatives(
            literal("wee"),
            literal("week")),
        alternatives(
            literal("knights"),
            literal("night")));
    simpleTest(m, "weeknights");
    m = sequence(
        alternatives(
            literal("we"),
            literal("wee"),
            literal("week"),
            literal("frob")),
        alternatives(
            literal("knights"),
            literal("night"),
            literal("day")));
    simpleTest(m, "weeknights");
    simpleTest(literal("abcdefghijklmnop"), "abcdefghijklmnop");
    simpleTest(literal("abcdefghijklmnopqrstuv"), "abcdefghijklmnopqrstuv");
    extendedRepeats(GREEDY_REPEATER);
    extendedRepeats(LAZY_REPEATER);
  }

  private void extendedRepeats(Repeater r) {
    Matcher m;
    simpleTest(
        sequence(
            literal("a"),
            r.star(literal("b")),
            literal("c")),
        "abc");
    simpleTest(
        sequence(
            literal("a"),
            r.plus(literal("b")),
            literal("c")),
        "abc");
    simpleTest(
        sequence(
            literal("a"),
            r.optional(literal("b")),
            literal("c")),
        "abc");
    m = sequence(
        literal("a"),
        r.plus(oneOf("0123456789")),
        literal("c"));
    simpleTest(m, "a019c");
    m = sequence(
        literal("A"),
        r.plus(oneOf("abcdefghijklmnopqrstuvwxyz")),
        literal("C"));
    simpleTest(m, "AabC");
    m = sequence(
        literal("a"),
        r.plus(oneOf("ABCDEFGHIJKLMNOPQRSTUVWXYZ")),
        literal("c"));
    simpleTest(m, "aBCc");
    m = sequence(
        literal("a"),
        r.repeat(oneOf("ab"), 20));
    simpleTest(m, "aaaaabaaaabaaaabaaaab");
    m = sequence(
        literal("a"),
        r.star(oneOf("Bc")),
        literal("d"));
    simpleTest(m, "acBd");
    simpleTest(m, "aBcd");
    simpleTest(m, "aBcBcBd");
    failTest(m, "aBCd");
    failTest(m, "abcd");
    failTest(m, "abBCcd");
    m = sequence(
        literal("a"),
        r.plus(
            sequence(
                r.optional(literal("b")),
                literal("c"))),
        literal("d"));
    simpleTest(m, "accd");
    assertLength(0).run(
        r.star(literal("a")),
        "b");
    m = alternatives(
        sequence(
            literal("CC"),
            oneOf("13"),
            literal("1")),
        sequence(
            oneOf("23"),
            oneOf("EO"),
            oneOf("123"),
            oneOf("Es"),
            oneOf("12"),
            r.repeat(literal("a"), 15),
            literal("aa"),
            oneOf("34"),
            oneOf("EW"),
            literal("aaaaaaa"),
            oneOf("X"),
            literal("a")));
    simpleTest(m, "CC11");
  }

  // Ripped off from "grep/tests/khadafy.*".
  public void testMuammarQaddafi() {
    LOGGER.info("start test: testMuammarQaddafi");
    Matcher m
        = sequence(
            literal("M"),
            oneOf("ou"),
            literal("'").optional(),
            literal("a"),
            literal("m").plus(),
            oneOf("ae"),
            literal("r "),
            anyChar().star(),
            sequence(
                oneOf("AEae"),
                literal("l"),
                oneOf("- "))
            .optional(),
            oneOf("GKQ"),
            literal("h").optional(),
            oneOf("aeu").plus(),
            sequence(
                oneOf("dtz"),
                oneOf("dhz").optional())
            .plus(),
            literal("af"),
            oneOf("iy"));
    simpleTest(m, "Muammar Qaddafi");
    simpleTest(m, "Mo'ammar Gadhafi");
    simpleTest(m, "Muammar Kaddafi");
    simpleTest(m, "Muammar Qadhafi");
    simpleTest(m, "Moammar El Kadhafi");
    simpleTest(m, "Muammar Gadafi");
    simpleTest(m, "Mu'ammar al-Qadafi");
    simpleTest(m, "Moamer El Kazzafi");
    simpleTest(m, "Moamar al-Gaddafi");
    simpleTest(m, "Mu'ammar Al Qathafi");
    simpleTest(m, "Muammar Al Qathafi");
    simpleTest(m, "Mo'ammar el-Gadhafi");
    simpleTest(m, "Moamar El Kadhafi");
    simpleTest(m, "Muammar al-Qadhafi");
    simpleTest(m, "Mu'ammar al-Qadhdhafi");
    simpleTest(m, "Mu'ammar Qadafi");
    simpleTest(m, "Moamar Gaddafi");
    simpleTest(m, "Mu'ammar Qadhdhafi");
    simpleTest(m, "Muammar Khaddafi");
    simpleTest(m, "Muammar al-Khaddafi");
    simpleTest(m, "Mu'amar al-Kadafi");
    simpleTest(m, "Muammar Ghaddafy");
    simpleTest(m, "Muammar Ghadafi");
    simpleTest(m, "Muammar Ghaddafi");
    simpleTest(m, "Muamar Kaddafi");
    simpleTest(m, "Muammar Quathafi");
    simpleTest(m, "Muammar Gheddafi");
    simpleTest(m, "Muamar Al-Kaddafi");
    simpleTest(m, "Moammar Khadafy");
    simpleTest(m, "Moammar Qudhafi");
    simpleTest(m, "Mu'ammar al-Qaddafi");
    simpleTest(m, "Mu'ammar Muhammad Abu Minyar al-Qadhafi");
  }

  // Ripped off from "grep/tests/spencer1.*".
  public void testSpencer() {
    LOGGER.info("start test: testSpencer");
    Matcher m = literal("abc");
    simpleTest(m, "abc");
    failTest(m, "xbc");
    failTest(m, "axc");
    failTest(m, "abx");
    m = sequence(
        atStart(),
        literal("abc"),
        atEnd());
    simpleTest(m, "abc");
    failTest(m, "abcc");
    m = sequence(
        atStart(),
        literal("abc"));
    assertLength(3).run(m, "abcc");
    assertLength(0).run(atStart(), "abcc");
    simpleTest(atEnd(), "");
    failTest(atEnd(), "a");
    m = sequence(
        literal("a"),
        anyChar(),
        literal("c"));
    simpleTest(m, "abc");
    simpleTest(m, "axc");
    m = sequence(
        literal("a"),
        oneOf("bc"),
        literal("d"));
    failTest(m, "abc");
    simpleTest(m, "abd");
    m = sequence(
        literal("a"),
        oneOf("bcd"),
        literal("e"));
    failTest(m, "abd");
    simpleTest(m, "ace");
    m = sequence(
        literal("a"),
        oneOf("bcd"));
    simpleTest(m, "ac");
    failTest(m, "aac");
    m = sequence(
        literal("a"),
        oneOf(CharSet.make("bc").invert()),
        literal("d"));
    simpleTest(m, "aed");
    failTest(m, "abd");
    simpleTest(
        alternatives(
            literal("a"),
            literal("b"),
            literal("c"),
            literal("d"),
            literal("e")),
        "e");
    simpleTest(
        sequence(
            alternatives(
                literal("a"),
                literal("b"),
                literal("c"),
                literal("d"),
                literal("e")),
            literal("f")),
        "ef");
    failTest(literal("multiple words of text"), "uh-uh");
    assertLength(14).run(literal("multiple words"), "multiple words, yeah");
    spencerRepeats(GREEDY_REPEATER);
    spencerRepeats(LAZY_REPEATER);
  }

  private void spencerRepeats(Repeater r) {
    Matcher m;
    m = sequence(
        literal("a"),
        r.star(literal("b")),
        literal("c"));
    simpleTest(m, "abc");
    m = sequence(
        literal("a"),
        r.star(literal("b")),
        literal("bc"));
    simpleTest(m, "abc");
    simpleTest(m, "abbc");
    simpleTest(m, "abbbbc");
    m = sequence(
        literal("a"),
        r.plus(literal("b")),
        literal("bc"));
    failTest(m, "abc");
    simpleTest(m, "abbc");
    simpleTest(m, "abbbbc");
    failTest(m, "abq");
    m = sequence(
        literal("a"),
        r.optional(literal("b")),
        literal("bc"));
    simpleTest(m, "abc");
    simpleTest(m, "abbc");
    failTest(m, "abbbbc");
    m = sequence(
        literal("a"),
        r.optional(literal("b")),
        literal("c"));
    simpleTest(m, "abc");
    m = sequence(
        literal("a"),
        r.star(anyChar()),
        literal("c"));
    simpleTest(m, "axyzc");
    failTest(m, "axyzd");
    m = sequence(
        r.plus(literal("a")),
        r.plus(literal("b")),
        literal("c"));
    simpleTest(m, "abc");
    simpleTest(m, "aabbc");
    failTest(m, "aabbabc");
    assertLength(0).run(r.star(r.star(literal("a"))), "-");
    assertLength(0).run(r.plus(literal("")), "-");
    assertLength(0).run(r.plus(r.star(literal("a"))), "-");
    assertLength(0).run(r.optional(r.star(literal("a"))), "-");
    assertLength(0).run(
        r.star(
            alternatives(
                literal("a"),
                sequence())),
        "-");
    simpleTest(
        alternatives(
            r.plus(literal("a")),
            literal("b"))
        .star(),
        "ab");
    assertLength(0).run(
        alternatives(
            r.plus(literal("a")),
            literal("b"))
        .lazyStar(),
        "ab");
    simpleTest(
        alternatives(
            r.plus(literal("a")),
            literal("b"))
        .plus(),
        "ab");
    assertLength(1).run(
        alternatives(
            r.plus(literal("a")),
            literal("b"))
        .lazyPlus(),
        "ab");
    m =
        alternatives(
            r.plus(literal("a")),
            literal("b"))
        .optional();
    assertLength(1).run(m, "ab");
    assertLength(1).run(m, "ba");
    m =
        alternatives(
            r.plus(literal("a")),
            literal("b"))
        .lazyOptional();
    assertLength(0).run(m, "ab");
    assertLength(0).run(m, "ba");
    assertLength(0).run(oneOf(CharSet.make("ab").invert()).lazyStar(), "cde");
    simpleTest(oneOf(CharSet.make("ab").invert()).star(), "cde");
    simpleTest(
        sequence(
            r.star(oneOf("abc")),
            literal("d")),
        "abbbcd");
    simpleTest(
        sequence(
            r.star(oneOf("abc")),
            literal("bcd")),
        "abcd");
    simpleTest(
        sequence(
            literal("abc"),
            r.star(literal("d")),
            literal("efg")),
        "abcdefg");
    assertLength(8).and(assertDict("x", "beri")).run(
        sequence(
            sequence(anyChar(), anyChar(), anyChar(), anyChar()).putMatchedString("x"),
            r.star(anyChar()),
            getMatcher("x")),
        "beriberi");
  }

  // **************** Helper methods ****************

  private void simpleTest(Matcher m, String string) {
    assertLength(string.length()).run(m, string);
  }

  private void failTest(Matcher m, String string) {
    assertFail().run(m, string);
  }

  private SucceedResult runMatch(Matcher m, String string) {
    return m.topLevelMatch(string);
  }

  private List<SucceedResult> runMatches(Matcher m, List<String> strings) {
    List<SucceedResult> results = Lists.newArrayList();
    for (String string : strings) {
      results.add(runMatch(m, string));
    }
    return results;
  }

  private List<SucceedResult> runAllMatches(Matcher m, String string) {
    List<SucceedResult> results = Lists.newArrayList();
    SucceedResult result = m.topLevelMatch(string);
    while (result != null) {
      results.add(result);
      result = continueTopLevelMatch(result);
    }
    return results;
  }

  private static ResultAssertion assertFail() {
    return new ResultAssertion() {
      @Override
      public void run(SucceedResult result) {
        assertNull("Expected match to fail", result);
      }
    };
  }

  private static ResultAssertion assertLength(final int expectedLength) {
    return (expectedLength < 0)
        ? assertFail()
        : new ResultAssertion() {
            @Override
            public void run(SucceedResult result) {
              assertNotNull("Expected match to succeed", result);
              assertEquals("Expected different match length: ",
                  expectedLength,
                  result.getState().getPosition().countChars());
            }
          };
  }

  private static Runner<List<SucceedResult>> assertLengths(int... expectedLengths) {
    List<ResultAssertion> assertions = Lists.newArrayList();
    for (int expectedLength : expectedLengths) {
      assertions.add(assertLength(expectedLength));
    }
    return mapAssertions(assertions);
  }

  private static ResultAssertion assertStack(Object... values) {
    return assertStack(ImmutableList.copyOf(values));
  }

  private static ResultAssertion assertStack(final List<? extends Object> expected) {
    return new ResultAssertion() {
      @Override
      public void run(SucceedResult result) {
        assertEquals(expected, result.getState().getStack().toList());
      }
    };
  }

  private static Runner<List<SucceedResult>> assertDicts(
      List<? extends Map<? extends Object, ? extends Object>> expected) {
    List<ResultAssertion> assertions = Lists.newArrayList();
    for (Map<? extends Object, ? extends Object> e : expected) {
      assertions.add(assertDict(e));
    }
    return mapAssertions(assertions);
  }

  private static ResultAssertion assertDict(
      final Map<? extends Object, ? extends Object> expected) {
    return new ResultAssertion() {
      @Override
      public void run(SucceedResult result) {
        assertEquals(expected, result.getState().getDict().toMap());
      }
    };
  }

  private static ResultAssertion assertDict(Object key1, Object value1) {
    return assertDict(ImmutableMap.of(key1, value1));
  }

  private interface Runner<T> {
    public void run(T result);
  }

  private abstract static class ResultAssertion implements Runner<SucceedResult> {
    public void run(Matcher m, String string) {
      run(m.topLevelMatch(string));
    }

    public ResultAssertion and(final ResultAssertion a2) {
      final ResultAssertion a1 = this;
      return new ResultAssertion() {
        @Override
        public void run(SucceedResult result) {
          a1.run(result);
          a2.run(result);
        }
      };
    }
  }

  private static Runner<List<SucceedResult>> mapAssertions(final List<ResultAssertion> assertions) {
    return new Runner<List<SucceedResult>>() {
      @Override
      public void run(List<SucceedResult> results) {
        assertEquals(assertions.size(), results.size());
        for (int i = 0; i < assertions.size(); i += 1) {
          assertions.get(i).run(results.get(i));
        }
      }
    };
  }

  private interface Repeater {
    public Matcher repeat(Matcher m, int low, int high);
    public Matcher repeat(Matcher m, int n);
    public Matcher star(Matcher m);
    public Matcher plus(Matcher m);
    public Matcher optional(Matcher m);
  }

  private static final Repeater GREEDY_REPEATER =
      new Repeater() {
        @Override
        public Matcher repeat(Matcher m, int low, int high) {
          return m.repeat(low, high);
        }

        @Override
        public Matcher repeat(Matcher m, int n) {
          return m.repeat(n);
        }

        @Override
        public Matcher star(Matcher m) {
          return m.star();
        }

        @Override
        public Matcher plus(Matcher m) {
          return m.plus();
        }

        @Override
        public Matcher optional(Matcher m) {
          return m.optional();
        }
      };

  private static final Repeater LAZY_REPEATER =
      new Repeater() {
        @Override
        public Matcher repeat(Matcher m, int low, int high) {
          return m.lazyRepeat(low, high);
        }

        @Override
        public Matcher repeat(Matcher m, int n) {
          return m.lazyRepeat(n);
        }

        @Override
        public Matcher star(Matcher m) {
          return m.lazyStar();
        }

        @Override
        public Matcher plus(Matcher m) {
          return m.lazyPlus();
        }

        @Override
        public Matcher optional(Matcher m) {
          return m.lazyOptional();
        }
      };
}
