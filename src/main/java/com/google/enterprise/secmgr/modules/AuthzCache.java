// Copyright 2010 Google Inc.
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

package com.google.enterprise.secmgr.modules;

import com.google.common.base.Preconditions;
import com.google.common.cache.CacheBuilder;
import com.google.enterprise.secmgr.common.AuthzStatus;
import java.util.Objects;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;

/**
 * The cache where we store the result of an authorization check.
 * Entries in this cache live for a limited amount of time.
 *
 */
@ThreadSafe
class AuthzCache {
  @GuardedBy("itself") private final ConcurrentMap<Key, AuthzStatus> map;

  /**
   * @param cacheEntryTimeoutSecs how long in seconds each cache entry lives
   * @throws IllegalArgumentException when cacheEntryTimeoutSecs is negative
   */
  AuthzCache(int cacheEntryTimeoutSecs) {
    Preconditions.checkArgument(cacheEntryTimeoutSecs >= 0,
        "cacheEntryTimeoutSecs must be non-negative: %s", cacheEntryTimeoutSecs);
    map =
        CacheBuilder.newBuilder()
            .softValues()
            .expireAfterWrite(cacheEntryTimeoutSecs, TimeUnit.SECONDS)
            .<AuthzCache.Key, AuthzStatus>build()
            .asMap();
  }

  /**
   * Adds entry to cache that maps user identity and url to
   * what the user is authorized to see with respect to that url.
   *
   * @param id the identity of the user
   * @param url the url in the user's search results
   * @param authorized whether the user is authorized to see this url
   */
  @SuppressWarnings("GuardedByChecker")
  void addEntry(String id, String url, AuthzStatus authorized) {
    map.put(new Key(id, url), authorized);
  }

  @SuppressWarnings("GuardedByChecker")
  void clear() {
    map.clear();
  }

  /**
   * Looks up a cache value.
   *
   * @param id the identity of the user
   * @param url the url the user is trying to access
   * @return which actions the user is authorized for; null on miss
   */
  @SuppressWarnings("GuardedByChecker")
  AuthzStatus lookup(String id, String url) {
    return map.get(new Key(id, url));
  }

  static final class Key {
    private final String id;
    private final String url;

    Key(String id, String url) {
      this.id = id;
      this.url = url;
    }

    @Override
    public int hashCode() {
      return Objects.hash(id, url);
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) { return true; }
      if (!(o instanceof Key)) { return false; }
      Key k = (Key) o;
      return Objects.equals(id, k.id)
          && Objects.equals(url, k.url);
    }
  }
}
