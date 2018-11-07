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
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.enterprise.secmgr.generators.Generator;
import com.google.enterprise.secmgr.generators.Generators;
import java.util.List;
import java.util.Map;
import junit.framework.TestCase;

/**
 * Unit tests of the matcher dictionary.
 *
 */
public final class DictTest extends TestCase {
  private static final String KEY1 = "key1";
  private static final Object KEY2 = new Object();
  private static final Object KEY3 = new Object();
  private static final String VALUE1 = "value1";
  private static final Object VALUE2 = new Object();
  private static final Object VALUE3 = new Object();

  private static final Generator KEYS = Generators.of(KEY1, KEY2, KEY3);
  private static final Generator VALUES = Generators.of(VALUE1, VALUE2, VALUE3);
  private static final Generator PAIRS = Generators.crossProduct(KEYS, VALUES);

  public void testEmpty() {
    Dict dict = Dict.empty();
    assertNotNull(dict);
    assertNull(dict.get(KEY1));
    assertNull(dict.get(KEY2));
    assertNull(dict.get(KEY3));
  }

  public void testEmptyWithNull() {
    tryWithNull(Dict.empty());
  }

  public void testEmptyBind() {
    Dict dict = Dict.empty();
    for (Object pair : PAIRS) {
      Object[] kv = (Object[]) pair;
      Dict dict1 = dict.put(kv[0], kv[1]);
      for (Object key : KEYS) {
        Object value = dict1.get(key);
        if (key.equals(kv[0])) {
          assertEquals(kv[1], value);
        } else {
          assertNull(value);
        }
      }
    }
  }

  public void testNonEmptyBind() {
    Dict dict0 = Dict.empty();
    for (Object pair1 : PAIRS) {
      Object[] kv1 = (Object[]) pair1;
      Dict dict1 = dict0.put(kv1[0], kv1[1]);
      for (Object pair2 : PAIRS) {
        Object[] kv2 = (Object[]) pair2;
        Dict dict2 = dict1.put(kv2[0], kv2[1]);
        for (Object key : KEYS) {
          Object value = dict2.get(key);
          if (key.equals(kv2[0])) {
            assertEquals(kv2[1], value);
          } else if (key.equals(kv1[0])) {
            assertEquals(kv1[1], value);
          } else {
            assertNull(value);
          }
        }
      }
    }
  }

  public void testIterator() {
    Dict dict0 = Dict.empty();
    assertEquals(expectedIterable(),
        ImmutableList.copyOf(dict0));
    Dict dict1 = dict0.put(KEY1, VALUE1);
    assertEquals(expectedIterable(KEY1, VALUE1),
        ImmutableList.copyOf(dict1));
    Dict dict2 = dict1.put(KEY2, VALUE2);
    assertEquals(expectedIterable(KEY2, VALUE2, KEY1, VALUE1),
        ImmutableList.copyOf(dict2));
    Dict dict3 = dict2.put(KEY1, VALUE3);
    assertEquals(expectedIterable(KEY1, VALUE3, KEY2, VALUE2, KEY1, VALUE1),
        ImmutableList.copyOf(dict3));
  }

  public void testToMap() {
    Dict dict0 = Dict.empty();
    assertEquals(expectedMap(), dict0.toMap());
    Dict dict1 = dict0.put(KEY1, VALUE1);
    assertEquals(expectedMap(KEY1, VALUE1), dict1.toMap());
    Dict dict2 = dict1.put(KEY2, VALUE2);
    assertEquals(expectedMap(KEY1, VALUE1, KEY2, VALUE2), dict2.toMap());
    Dict dict3 = dict2.put(KEY1, VALUE3);
    assertEquals(expectedMap(KEY1, VALUE3, KEY2, VALUE2), dict3.toMap());
  }

  private Map<Object, Object> expectedMap(Object... bindings) {
    Map<Object, Object> expected = Maps.newHashMap();
    for (int i = 0; i < bindings.length; i += 2) {
      expected.put(bindings[i], bindings[i + 1]);
    }
    return expected;
  }

  private List<Map.Entry<Object, Object>> expectedIterable(Object... bindings) {
    List<Map.Entry<Object, Object>> expected = Lists.newArrayList();
    for (int i = 0; i < bindings.length; i += 2) {
      expected.add(Maps.immutableEntry(bindings[i], bindings[i + 1]));
    }
    return expected;
  }

  private void tryWithNull(Dict dict) {
    try {
      dict.get(null);
      fail("Expected NullPointerException");
    } catch (NullPointerException e) {
      // pass
    }
    try {
      dict.put(null, VALUE1);
      fail("Expected NullPointerException");
    } catch (NullPointerException e) {
      // pass
    }
    try {
      dict.put(KEY1, null);
      fail("Expected NullPointerException");
    } catch (NullPointerException e) {
      // pass
    }
  }
}
