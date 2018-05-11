// Copyright 2009 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.policychecker;

import com.google.common.collect.Maps;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

public class CompactExactMatchMap<V> implements Map<String, Entry<String, V>> {

  private final Map<String, V> internalMap = new MDUrlMap<V>();

  private V clobberEntry(Entry<String, V> e) {
    return e.getValue();
  }

  /* @Override */
  public void clear() {
    internalMap.clear();
  }

  /* @Override */
  public boolean containsKey(Object key) {
    return internalMap.containsKey(key);
  }

  /* @Override */
  public boolean containsValue(Object value) {
    throw new UnsupportedOperationException();
  }

  /* @Override */
  public Set<Entry<String, Entry<String, V>>> entrySet() {
    throw new UnsupportedOperationException();
  }

  /* @Override */
  public Entry<String, V> get(Object key) {
    V value = internalMap.get(key);
    return makeReturnValue(value);
  }

  private Entry<String, V> makeReturnValue(V value) {
    if (value == null) {
      return null;
    }
    return Maps.immutableEntry("", value);
  }

  /* @Override */
  public boolean isEmpty() {
    return internalMap.isEmpty();
  }

  /* @Override */
  public Set<String> keySet() {
    return internalMap.keySet();
  }

  /* @Override */
  public Entry<String, V> put(String key, Entry<String, V> value) {
    V internalValue = internalMap.put(key, clobberEntry(value));
    return makeReturnValue(internalValue);
  }

  /* @Override */
  public void putAll(Map<? extends String, ? extends Entry<String, V>> t) {
    for (Entry<? extends String, ? extends Entry<String, V>> e: t.entrySet()) {
      internalMap.put(e.getKey(), e.getValue().getValue());
    }
  }

  /* @Override */
  public Entry<String, V> remove(Object key) {
    V internalValue = internalMap.remove(key);
    return makeReturnValue(internalValue);
  }

  /* @Override */
  public int size() {
    return internalMap.size();
  }

  /* @Override */
  public Collection<Entry<String, V>> values() {
    throw new UnsupportedOperationException();
  }
}
