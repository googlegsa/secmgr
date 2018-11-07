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

import static com.google.enterprise.secmgr.matcher.UnicodeTest.TEST_POINTS;
import static com.google.enterprise.secmgr.matcher.UnicodeTest.stringify;

import com.google.common.collect.ImmutableList;
import java.util.logging.Level;
import java.util.logging.Logger;
import junit.framework.TestCase;

/**
 * Unit tests of character sets.
 *
 */
public final class CharSetTest extends TestCase {
  private static final Logger LOGGER = Logger.getLogger(CharSetTest.class.getName());

  public void testNone() {
    for (int cp : TEST_POINTS) {
      assertFalse(CharSet.NONE.isMember(cp));
    }
  }

  public void testAll() {
    for (int cp : TEST_POINTS) {
      assertEquals(
          Unicode.isCharacter(cp),
          CharSet.ALL.isMember(cp));
    }
  }

  public void testAscii() {
    for (int cp : TEST_POINTS) {
      assertEquals(
          cp >= 0 && cp < 0x80,
          CharSet.US_ASCII.isMember(cp));
    }
  }

  public void testSingles() {
    for (int cp1 : TEST_POINTS) {
      if (Character.isValidCodePoint(cp1)) {
        CharSet cs = CharSet.builder().add(cp1).build();
        for (int cp2 : TEST_POINTS) {
          assertEquals(cp2 == cp1 && Unicode.isCharacter(cp2), cs.isMember(cp2));
        }
      } else {
        try {
          CharSet.builder().add(cp1);
          fail(String.format("Expected IllegalArgumentException for %X", cp1));
        } catch (IllegalArgumentException e) {
          // pass
        }
      }
    }
  }

  public void testSingleRanges() {
    for (int cp1 : TEST_POINTS) {
      if (Character.isValidCodePoint(cp1)) {
        CharSet cs = CharSet.builder().add(cp1, cp1 + 1).build();
        for (int cp2 : TEST_POINTS) {
          assertEquals(cp2 == cp1 && Unicode.isCharacter(cp2), cs.isMember(cp2));
        }
      } else {
        try {
          CharSet.builder().add(cp1, cp1 + 1);
          fail(String.format("Expected IllegalArgumentException for %X", cp1));
        } catch (IllegalArgumentException e) {
          // pass
        }
      }
    }
  }

  public void testSingleString() {
    for (int i = 0; i < TEST_POINTS.size(); i += 1) {
      int cp1 = TEST_POINTS.get(i);
      if (Character.isValidCodePoint(cp1)) {
        String s = stringify(TEST_POINTS, i, 1);
        String js = UnicodeTest.toJavaLiteral(s);
        CharSet cs;
        if (Unicode.isCharacter(cp1)) {
          try {
            cs = CharSet.builder().add(s).build();
          } catch (IllegalArgumentException e) {
            LOGGER.log(Level.WARNING, "Unexpected exception: ", e);
            fail(String.format("Building set %s: didn't expect IllegalArgumentException", js));
            continue;
          }
        } else {
          try {
            cs = CharSet.builder().add(s).build();
            fail(String.format("Building set %s: expected IllegalArgumentException", js));
          } catch (IllegalArgumentException e) {
            // pass
          }
          continue;
        }
        for (int cp2 : TEST_POINTS) {
          if (Character.isValidCodePoint(cp2)) {
            assertEquals(String.format("Comparing set of %s and code point %X: ", js, cp2),
                cp2 == cp1 && Unicode.isCharacter(cp2),
                cs.isMember(cp2));
          }
        }
      } else {
        try {
          stringify(TEST_POINTS, i, 1);
          fail(String.format("stringify code point %X: expected IllegalArgumentException", cp1));
        } catch (IllegalArgumentException e) {
          // pass
        }
      }
    }
  }

  public void testSimpleStrings() {
    trySimpleString("");
    trySimpleString("a");
    trySimpleString("ab");
    trySimpleString("abc");
    trySimpleString("abcefghijklmnopqrstuvwxyz");
  }

  public void testGetRanges() {
    assertEquals(
        ImmutableList.<CharSet.Range>of(),
        CharSet.NONE.getRanges());
    assertEquals(
        ImmutableList.of(CharSet.Range.make(0, Unicode.CODE_POINT_LIMIT)),
        CharSet.ALL.getRanges());
    assertEquals(
        ImmutableList.of(CharSet.Range.make('b', 'b' + 1)),
        CharSet.make("b").getRanges());
  }

  public void testInvert() {
    assertEquals(CharSet.ALL, CharSet.NONE.invert());
    assertEquals(
        ImmutableList.of(
            CharSet.Range.make(0, 'b'),
            CharSet.Range.make('b' + 1, Unicode.CODE_POINT_LIMIT)),
        CharSet.make("b").invert().getRanges());
    for (int cp1 : TEST_POINTS) {
      if (Character.isValidCodePoint(cp1)) {
        CharSet cs = CharSet.builder().add(cp1).build().invert();
        for (int cp2 : TEST_POINTS) {
          assertEquals(cp2 != cp1 && Unicode.isCharacter(cp2), cs.isMember(cp2));
        }
      }
    }
  }

  private void trySimpleString(String s) {
    CharSet cs = CharSet.make(s);
    for (int cp : TEST_POINTS) {
      assertEquals(s.indexOf(cp) >= 0, cs.isMember(cp));
    }
  }
}
