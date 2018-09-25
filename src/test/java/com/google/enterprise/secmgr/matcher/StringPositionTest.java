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

import com.google.common.collect.Lists;
import java.util.List;
import junit.framework.TestCase;

/**
 * Unit tests of {@link StringPosition}.
 *
 */
public final class StringPositionTest extends TestCase {

  public void testString0() {
    tryString("");
  }

  public void testString1() {
    tryString("a");
  }

  public void testString2() {
    tryString("ab");
  }

  public void testString5() {
    tryString("abcde");
  }

  private void tryString(String string) {
    List<Position> ps = Lists.newArrayList();
    Position p0 = StringPosition.make(string);
    int ncp = Unicode.length(string);
    Position p = p0;
    for (int pi = 0; pi <= ncp; pi += 1) {
      ps.add(p);

      // Test hasPrevChar and getPrevChar.
      if (pi > 0) {
        assertTrue(p.hasPrevChar());
        assertEquals(Unicode.get(string, pi - 1), p.getPrevChar());
      } else {
        assertFalse(p.hasPrevChar());
        try {
          p.getPrevChar();
          fail("Expected IndexOutOfBoundsException");
        } catch (IndexOutOfBoundsException e) {
          // pass
        }
      }

      // Test hasChar, getChar, and nextPosition().
      Position p1;
      if (pi < ncp) {
        assertTrue(p.hasChar());
        assertEquals(Unicode.get(string, pi), p.getChar());
        assertEquals(string.substring(0, string.offsetByCodePoints(0, pi)), p.getString(p0));
        assertEquals(pi, p.countChars(p0));
        p1 = p.nextPosition();
        // Guarantee that this position is different from all the previous ones.
        for (Position p2 : ps) {
          assertFalse(p2.equals(p1));
        }
      } else {
        assertFalse(p.hasChar());
        try {
          p.getChar();
          fail("Expected IndexOutOfBoundsException");
        } catch (IndexOutOfBoundsException e) {
          // pass
        }
        try {
          p.nextPosition();
          fail("Expected IndexOutOfBoundsException");
        } catch (IndexOutOfBoundsException e) {
          // pass
        }
        p1 = null;
      }

      // Move to the next position.
      if (p1 == null) {
        break;
      }
      p = p1;
    }

    // Test hasChars, getString, and nextPosition(int).
    for (int pi = 0; pi <= ncp; pi += 1) {
      p = ps.get(pi);
      int pic = string.offsetByCodePoints(0, pi);
      for (int j = -8; j <= 8; j += 1) {
        if (j < 0) {
          try {
            p.hasChars(j);
            fail("Expected IllegalArgumentException");
          } catch (IllegalArgumentException e) {
            // pass
          }
          try {
            p.getString(j);
            fail("Expected IllegalArgumentException");
          } catch (IllegalArgumentException e) {
            // pass
          }
          try {
            p.nextPosition(j);
            fail("Expected IllegalArgumentException");
          } catch (IllegalArgumentException e) {
            // pass
          }
        } else if (pi + j <= ncp) {
          assertTrue(p.hasChars(j));
          assertEquals(string.substring(pic, string.offsetByCodePoints(pic, j)), p.getString(j));
          assertEquals(ps.get(pi + j), p.nextPosition(j));
        } else {
          assertFalse(p.hasChars(j));
          try {
            p.getString(j);
            fail("Expected IndexOutOfBoundsException");
          } catch (IndexOutOfBoundsException e) {
            // pass
          }
          try {
            p.nextPosition(j);
            fail("Expected IndexOutOfBoundsException");
          } catch (IndexOutOfBoundsException e) {
            // pass
          }
        }
      }
    }
  }
}
