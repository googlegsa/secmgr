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

import com.google.common.base.Predicate;
import com.google.common.collect.ImmutableList;
import java.util.List;
import junit.framework.TestCase;

/**
 * Unit tests of Unicode utilities.
 *
 */
public final class UnicodeTest extends TestCase {
  // Individual code points to test.
  public static final List<Integer> TEST_POINTS = computeTestPoints();

  private static List<Integer> computeTestPoints() {
    ImmutableList.Builder<Integer> builder = ImmutableList.builder();
    int j = 0;
    builder.add(Integer.MIN_VALUE);
    builder.add(-1);
    for (int i = 0; i < 0x100; i += 1) {
      builder.add(i);
    }
    for (int i = 0x0100; i < 0x10000; i += 0x0100) {
      builder.add(i);
      builder.add(i + 1);
      builder.add(i + 0x00FF);
    }
    for (int i = 0xD800; i < 0xE000; i += 1) {
      builder.add(i);
    }
    for (int i = 0xFDD0; i < 0xFDF0; i += 1) {
      builder.add(i);
    }
    builder.add(0xFFFE);
    for (int i = 0x10000; i < 0x110000; i += 0x10000) {
      builder.add(i);
      builder.add(i + 1);
      builder.add(i + 0xFFFE);
      builder.add(i + 0xFFFF);
    }
    builder.add(0x110000);
    builder.add(Integer.MAX_VALUE);
    return builder.build();
  }

  public void testIsCodePoint() {
    tryPredicate("isCodePoint",
        new Predicate<Integer>() {
          public boolean apply(Integer cp) {
            return Character.isValidCodePoint(cp);
          }
        },
        new Predicate<Integer>() {
          public boolean apply(Integer cp) {
            return Unicode.isCodePoint(cp);
          }
        });
  }

  public void testIsSurrogate() {
    tryPredicate("isSurrogate",
        new Predicate<Integer>() {
          public boolean apply(Integer cp) {
            return cp >= 0xD800 && cp < 0xE000;
          }
        },
        new Predicate<Integer>() {
          public boolean apply(Integer cp) {
            return Unicode.isSurrogate(cp);
          }
        });
  }

  public void testIsScalarValue() {
    tryPredicate("isScalarValue",
        new Predicate<Integer>() {
          public boolean apply(Integer cp) {
            return (cp >= 0 && cp < 0xD800)
                || (cp >= 0xE000 && cp < 0x110000);
          }
        },
        new Predicate<Integer>() {
          public boolean apply(Integer cp) {
            return Unicode.isScalarValue(cp);
          }
        });
  }

  public void testIsCharacter() {
    tryPredicate("isCharacter",
        new Predicate<Integer>() {
          public boolean apply(Integer cp) {
            return (cp >= 0 && cp < 0xD800)
                || (cp >= 0xE000 && cp < 0xFDD0)
                || ((cp >= 0xFDF0 && cp < 0x110000)
                    && (cp & 0xFFFE) != 0xFFFE);
          }
        },
        new Predicate<Integer>() {
          public boolean apply(Integer cp) {
            return Unicode.isCharacter(cp);
          }
        });
  }

  public void testIsWellFormed() {
    for (int i = 0; i < TEST_POINTS.size(); i += 1) {
      if (Character.isValidCodePoint(TEST_POINTS.get(i))) {
        String s = stringify(TEST_POINTS, i, 1);
        assertEquals("testIsWellFormed, string " + toJavaLiteral(s) + ": ",
            Unicode.isCharacter(TEST_POINTS.get(i)),
            Unicode.isWellFormed(s));
      }
    }
  }

  public void testLength() {
    for (int i = 0; i < TEST_POINTS.size(); i += 1) {
      if (Character.isValidCodePoint(TEST_POINTS.get(i))) {
        String s = stringify(TEST_POINTS, i, 1);
        assertEquals("testLength, string " + toJavaLiteral(s) + ": ",
            1,
            Unicode.length(s));
      }
    }
  }

  private void tryPredicate(String tag, Predicate<Integer> expected, Predicate<Integer> actual) {
    for (int cp : TEST_POINTS) {
      assertEquals(String.format("%s, code point %X: ", tag, cp),
          expected.apply(cp), actual.apply(cp));
    }
  }

  public static String stringify(List<Integer> chars, int offset, int count) {
    int[] converted = new int[count];
    for (int i = 0; i < count; i += 1) {
      converted[i] = chars.get(offset + i);
    }
    return new String(converted, 0, count);
  }

  public static String toJavaLiteral(String s) {
    StringBuilder builder = new StringBuilder();
    builder.append('"');
    for (int i = 0; i < Unicode.length(s); i += 1) {
      int c = Unicode.get(s, i);
      if (c == '\\' || c == '"') {
        builder.append('\\');
      }
      if (c >= 0x10000) {
        builder.append(String.format("\\U%8X", c));
      } else if (c >= 0x80 || c <= 0x20) {
        builder.append(String.format("\\u%4X", c));
      } else {
        builder.append(c);
      }
    }
    builder.append('"');
    return builder.toString();
  }
}
