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

import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.generators.Generator;
import com.google.enterprise.secmgr.generators.Generators;
import java.util.NoSuchElementException;
import junit.framework.TestCase;

/**
 * Unit tests of the matcher value stack.
 *
 */
public final class ValueStackTest extends TestCase {
  private static final String VALUE1 = "value1";
  private static final Object VALUE2 = new Object();
  private static final Object VALUE3 = new Object();

  private static final Generator VALUES = Generators.of(VALUE1, VALUE2, VALUE3);

  public void testEmpty() {
    ValueStack stack0 = ValueStack.empty();
    assertNotNull(stack0);
    assertTrue(stack0.isEmpty());
    assertEquals(0, stack0.size());
    try {
      stack0.top();
      fail("Expected NoSuchElementException");
    } catch (NoSuchElementException e) {
      // pass
    }
    try {
      stack0.pop();
      fail("Expected NoSuchElementException");
    } catch (NoSuchElementException e) {
      // pass
    }
    assertEquals(ImmutableList.of(), ImmutableList.copyOf(stack0));
    assertEquals(ImmutableList.of(), stack0.toList());
  }

  public void testPush() {
    ValueStack stack0 = ValueStack.empty();
    for (Object value1 : VALUES) {
      ValueStack stack1 = stack0.push(value1);
      assertFalse(stack1.isEmpty());
      assertEquals(1, stack1.size());
      assertEquals(value1, stack1.top());
      assertEquals(stack0, stack1.pop());
      assertEquals(ImmutableList.of(value1), ImmutableList.copyOf(stack1));
      assertEquals(ImmutableList.of(value1), stack1.toList());
      for (Object value2 : VALUES) {
        ValueStack stack2 = stack1.push(value2);
        assertFalse(stack2.isEmpty());
        assertEquals(2, stack2.size());
        assertEquals(value2, stack2.top());
        assertEquals(stack1, stack2.pop());
        assertEquals(ImmutableList.of(value2, value1), ImmutableList.copyOf(stack2));
        assertEquals(ImmutableList.of(value1, value2), stack2.toList());
      }
    }
  }
}
