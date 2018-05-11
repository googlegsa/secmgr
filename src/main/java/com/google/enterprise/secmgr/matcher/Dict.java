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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;

import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * An implementation of a matcher dictionary.  This is similar to a {@link Map},
 * except that it's immutable and can be extended in constant time.
 * <p>
 * Kind of like a Lisp association list.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
public abstract class Dict implements Iterable<Map.Entry<Object, Object>> {
  @Nonnull private static final Dict EMPTY = new EmptyDict();

  private static final class EmptyDict extends Dict {
  }

  private static final class NonEmptyDict extends Dict {
    @Nonnull final Map.Entry<Object, Object> entry;
    @Nonnull final Dict rest;

    NonEmptyDict(Map.Entry<Object, Object> entry, Dict rest) {
      this.entry = entry;
      this.rest = rest;
    }
  }

  /**
   * Gets an empty dictionary.
   */
  @Nonnull
  public static Dict empty() {
    return EMPTY;
  }

  /**
   * Adds a new binding to this dictionary.
   *
   * @param key The binding's key.
   * @param value The binding's value.
   * @return A new dictionary with the added binding.
   */
  @Nonnull
  public Dict put(Object key, Object value) {
    Preconditions.checkNotNull(key);
    Preconditions.checkNotNull(value);
    return new NonEmptyDict(Maps.immutableEntry(key, value), this);
  }

  /**
   * Looks up a value in this dictionary.
   *
   * @param key The key to look up.
   * @return The value bound to {@code key}, or {@code null} if there isn't one.
   */
  @Nullable
  public Object get(Object key) {
    Preconditions.checkNotNull(key);
    for (Map.Entry<Object, Object> entry : this) {
      if (key.equals(entry.getKey())) {
        return entry.getValue();
      }
    }
    return null;
  }

  /**
   * Looks up a value in this dictionary.
   *
   * @param key The key to look up.
   * @return The value bound to {@code key}.
   * @throws NoSuchElementException if there's no binding for {@code key}.
   */
  @Nonnull
  public Object getRequired(Object key) {
    Object value = get(key);
    if (value == null) {
      throw new NoSuchElementException();
    }
    return value;
  }

  /**
   * Converts this dictionary to an immutable map.
   */
  @Nonnull
  public ImmutableMap<Object, Object> toMap() {
    Map<Object, Object> map = Maps.newHashMap();
    for (Map.Entry<Object, Object> entry : this) {
      if (!map.containsKey(entry.getKey())) {
        map.put(entry.getKey(), entry.getValue());
      }
    }
    return ImmutableMap.copyOf(map);
  }

  @Override
  public String toString() {
    return toMap().toString();
  }

  @Override
  public Iterator<Map.Entry<Object, Object>> iterator() {
    return new LocalIterator(this);
  }

  @NotThreadSafe
  private static final class LocalIterator implements Iterator<Map.Entry<Object, Object>> {
    Dict dict;

    LocalIterator(Dict dict) {
      this.dict = dict;
    }

    @Override
    public boolean hasNext() {
      return dict instanceof NonEmptyDict;
    }

    @Override
    public Map.Entry<Object, Object> next() {
      if (!(dict instanceof NonEmptyDict)) {
        throw new NoSuchElementException();
      }
      NonEmptyDict ned = (NonEmptyDict) dict;
      dict = ned.rest;
      return ned.entry;
    }

    @Override
    public void remove() {
      throw new UnsupportedOperationException();
    }
  }
}
