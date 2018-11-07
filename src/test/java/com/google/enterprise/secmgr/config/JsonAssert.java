// Copyright 2018 Google Inc.
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

package com.google.enterprise.secmgr.config;

import static com.google.common.truth.Truth.assertThat;

import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterators;
import com.google.common.collect.Lists;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Assert;

/**
 * Copy from java/com/google/is/crm/common/testing/util/junit/JsonAssert.java.
 * TODO: Move it to a common package.
 */
public class JsonAssert {

  public static void assertEquals(String expected, String actual) throws JSONException {
    assertEquals(new JSONObject(expected), new JSONObject(actual));
  }

  public static void assertEquals(JSONObject expected, JSONObject actual) throws JSONException {
    Assert.assertEquals(toString(expected), toString(actual));
  }

  /**
   * WARNING: This method recursively checks objects and is extremely inefficient.
   * Only use for small json sizes.
   */
  // TODO: Review all methods in this file and make sure that
  // all of them have the same order of expected/actual parameters.
  public static void assertRecursiveContentsAnyOrder(String expected, String actual)
      throws JSONException {
    Assert.assertTrue(recursiveContentsAnyOrder(new JSONObject(expected), new JSONObject(actual)));
  }

  public static void assertEquals(JSONArray expected, JSONArray actual) throws JSONException {
    Assert.assertEquals(toString(expected), toString(actual));
  }

  public static void assertContains(JSONArray actual, Object expected) {
    assertThat(flattenJsonArray(actual)).contains(flattenIfObjectIsJson(expected));
  }

  public static void assertNotContains(JSONArray actual, Object unexpected) {
    assertThat(flattenJsonArray(actual)).doesNotContain(flattenIfObjectIsJson(unexpected));
  }

  public static void assertContentsAnyOrder(JSONArray actual, Object... expected) {
    assertThat(flattenJsonElementInList(Lists.newArrayList(expected))).containsExactlyElementsIn(
        flattenJsonArray(actual));
  }

  public static void assertContentsInOrder(JSONArray actual, Object... expected) {
    Assert.assertEquals(
        flattenJsonElementInList(Lists.newArrayList(expected)), flattenJsonArray(actual));
  }

  /**
   * Asserts that the string elements in the jsonArray associated with the
   * jsonAttribute match the list of expected values.  It only checks the
   * individual values if the length is the same.
   *
   * @param jsonArray the jsonArray to check
   * @param jsonAttribute the attribute to use to get the the json value
   *     (i.e. jsonArray.getString(jsonAttribute))
   * @param expectedValues list of expected values to compare
   */
  public static void assertJsonArrayStringAttribute(JSONArray jsonArray,
      String jsonAttribute, String... expectedValues) throws JSONException {
    Assert.assertEquals(expectedValues.length, jsonArray.length());
    for (int i = 0; i < jsonArray.length(); i++) {
      Assert.assertEquals(expectedValues[i],
          jsonArray.getJSONObject(i).getString(jsonAttribute));
    }
  }

  private static List<?> flattenJsonElementInList(List<?> objs) {
    return Lists.transform(objs, new Function<Object, Object>(){
      @Override
      public Object apply(Object from) {
        return flattenIfObjectIsJson(from);
      }
    });
  }

  @SuppressWarnings("unchecked")
  private static Map<String, ?> flattenJsonObject(JSONObject jsonObject) {
    if (jsonObject == null) {
      return null;
    }

    Map<String, Object> jsonMap = new HashMap<>();
    Iterator<String> keys = jsonObject.keys();
    try {
      while (keys.hasNext()) {
        String key = keys.next();
        Object value = jsonObject.get(key);
        if (value instanceof JSONArray) {
          value = flattenJsonArray((JSONArray) value);
        } else if (value instanceof JSONObject) {
          value = flattenJsonObject((JSONObject) value);
        }
        jsonMap.put(key, value);
      }
    } catch (JSONException e) {
      throw new IllegalStateException("Not able to flatten the json.", e);
    }
    return jsonMap;
  }

  private static Object flattenIfObjectIsJson(Object obj){
    if (obj instanceof JSONArray) {
      return flattenJsonArray((JSONArray) obj);
    } else if (obj instanceof JSONObject) {
      return flattenJsonObject((JSONObject) obj);
    } else {
      return obj;
    }
  }

  private static List<?> flattenJsonArray(JSONArray jsonArray) {
    if (jsonArray == null) {
      return null;
    }

    List<Object> jsonList = new ArrayList<>();
    try {
      for (int i = 0; i < jsonArray.length(); i++) {
        Object value = jsonArray.get(i);
        if (value instanceof JSONArray) {
          value = flattenJsonArray((JSONArray) value);
        } else if (value instanceof JSONObject) {
          value = flattenJsonObject((JSONObject) value);
        }
        jsonList.add(value);
      }
    } catch (JSONException e) {
      throw new IllegalStateException("Not able to flatten the json.", e);
    }
    return jsonList;
  }

  private static String toString(Object object) throws JSONException {
    if (object instanceof JSONObject) {
      return toString((JSONObject) object);
    } else if (object instanceof JSONArray) {
      return toString((JSONArray) object);
    } else if (object instanceof String) {
      return "'" + object + "'";
    } else {
      return object.toString();
    }
  }

  @SuppressWarnings("unchecked")
  private static String toString(JSONObject object) throws JSONException {
    List<String> entries = new ArrayList<>();
    for (Iterator<String> iter = object.keys(); iter.hasNext();) {
      String key = iter.next();
      entries.add(String.format("%s: %s", key, toString(object.get(key))));
    }
    Collections.sort(entries);
    return "{\n" + Joiner.on("\n").join(entries) + "\n}";
  }

  private static String toString(JSONArray array) throws JSONException {
    List<String> entries = new ArrayList<>();
    for (int i = 0; i < array.length(); i++) {
      entries.add(toString(array.get(i)));
    }
    return "[\n" + Joiner.on("\n").join(entries) + "\n]";
  }

  private static boolean recursiveContentsAnyOrder(Object expected, Object actual)
      throws JSONException {
    if (expected instanceof JSONObject && actual instanceof JSONObject) {
      return recursiveContentsAnyOrder((JSONObject) expected, (JSONObject) actual);
    } else if (expected instanceof JSONArray && actual instanceof JSONArray) {
      return recursiveContentsAnyOrder((JSONArray) expected, (JSONArray) actual);
    } else {
      return Objects.equals(expected, actual);
    }
  }

  @SuppressWarnings("unchecked")
  private static boolean recursiveContentsAnyOrder(
      final JSONObject expected, final JSONObject actual) {
    if (expected.length() != actual.length()) {
      return false;
    }
    return Iterators.all(expected.keys(), new Predicate<String>() {
      @Override
      public boolean apply(String key) {
        try {
          Object expectedObj = expected.get(key);
          Object actualObj = actual.get(key);
          return recursiveContentsAnyOrder(expectedObj, actualObj);
        } catch (JSONException ignore) {
          throw new RuntimeException(ignore);
        }
      }
    });
  }

  private static boolean recursiveContentsAnyOrder(JSONArray expected, JSONArray actual)
      throws JSONException {
    if (expected.length() != actual.length()) {
      return false;
    }
    List<Object> expectedObjs = new ArrayList<>();
    for (int i = 0; i < expected.length(); i++) {
      expectedObjs.add(expected.get(i));
    }
    // Iterate through all combinations objects in the two arrays.
    for (int i = 0; i < actual.length(); i++) {
      for (int j = 0; j < expectedObjs.size(); j++) {
        if (recursiveContentsAnyOrder(expectedObjs.get(j), actual.get(i))) {
          expectedObjs.remove(j);
          break;
        }
      }
    }
    return expectedObjs.isEmpty();
  }
}
