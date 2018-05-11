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

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An implementation of {@code Map} that uses MD5.
 */
public class MDUrlMap<V> implements Map<String, V> {
  private final String algorithmName;
  private final Map<MD5Key, V> internalMap;

  public MDUrlMap() {
    this("MD5");
  }

  public MDUrlMap(String algorithmName) {
    this.algorithmName = algorithmName;
    this.internalMap = new ConcurrentHashMap<MD5Key, V>();
    try {
      // validate for fail fast
      MessageDigest md = MessageDigest.getInstance(algorithmName);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }


  private static class MD5Key {

    private final byte[] digest;

    public MD5Key(String s, String algorithmName) {
      MessageDigest md;
      try {
        md = MessageDigest.getInstance(algorithmName);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException(e);
      }
      byte[] bytes;
      try {
        bytes = s.getBytes("UTF-8");
      } catch (UnsupportedEncodingException e) {
        throw new IllegalStateException(e);
      }
      md.update(bytes);
      digest = md.digest();
    }

    @Override
    public int hashCode() {
      final int prime = 31;
      int result = 1;
      result = prime * result + Arrays.hashCode(digest);
      return result;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) return true;
      if (obj == null) return false;
      if (getClass() != obj.getClass()) return false;
      MD5Key other = (MD5Key) obj;
      if (!Arrays.equals(digest, other.digest)) return false;
      return true;
    }
  }

  MD5Key toHashedKey(String s) {
    return new MD5Key(s, algorithmName);
  }

  public void clear() {
    internalMap.clear();
  }

  public boolean containsKey(Object key) {
    String s = String.class.cast(key);
    MD5Key hashedKey = toHashedKey(s);
    return internalMap.containsKey(hashedKey);
  }

  public boolean containsValue(Object value) {
    return internalMap.containsValue(value);
  }

  public Set<Entry<String, V>> entrySet() {
    throw new UnsupportedOperationException();
  }

  public V get(Object key) {
    String s = String.class.cast(key);
    MD5Key hashedKey = toHashedKey(s);
    return internalMap.get(hashedKey);
  }

  public boolean isEmpty() {
    return internalMap.isEmpty();
  }

  public Set<String> keySet() {
    throw new UnsupportedOperationException();
  }

  public V put(String s, V value) {
    MD5Key hashedKey = toHashedKey(s);
    return internalMap.put(hashedKey, value);
  }

  public void putAll(Map<? extends String, ? extends V> t) {
    for (Entry<? extends String, ? extends V> e : t.entrySet()) {
      String s = e.getKey();
      V v = e.getValue();
      put(s, v);
    }
  }

  public V remove(Object key) {
    String s = String.class.cast(key);
    MD5Key hashedKey = toHashedKey(s);
    return internalMap.remove(hashedKey);
  }

  public int size() {
    return internalMap.size();
  }

  public Collection<V> values() {
    return internalMap.values();
  }

}
