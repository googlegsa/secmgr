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
package com.google.enterprise.common;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;

/**
 * StringLockManager provides a thread-safe and memory-efficient mechanism for
 * acquiring and releasing locks for on any given string.  As long as it is used
 * properly, StringLockManager is guaranteed to return the same lock object for
 * a given string as long as there exists at least one reference to that object
 * in the current environment.
 *
 * Proper usage of StringLockManager simply requires that each acquire for a
 * particular string be followed by a release, such as in the following idiom:
 *
 * Object lock = acquire("some string"));
 * try {
 *   synchronized (lock) {
 *     runSomeCode();
 *   }
 * } finally {
 *   release("some string");
 * }
 *
 * If all present holders have released the lock on a given string, that lock
 * is destroyed and subsequent calls to acquire may return a new and different
 * lock for the same string.
 *
 */
@ThreadSafe
public class StringLockManager {

  @GuardedBy("itself") private final ConcurrentMap<String, CountingLock> lockMap;

  public StringLockManager() {
    this.lockMap = new ConcurrentHashMap<>();
  }

  /**
   * Returns the lock for a given string if such a lock exists.  If the lock
   * doesn't exist, generates a new one. 
   *
   * @param str the string acquire a lock for
   * @return an object upon which the file path is locked
   */
  public CountingLock acquire(String str) {
    synchronized (lockMap) {
      if (!lockMap.containsKey(str)) {
        lockMap.put(str, new CountingLock());
      }

      return lockMap.get(str);
    }
  }

  /**
   * Releases a lock for a given string.
   *
   * @param str the string to release a lock for
   */
  public void release(String str) {
    synchronized (lockMap) {
      if (lockMap.containsKey(str)) {
        if (lockMap.get(str).release() <= 0) {
          lockMap.remove(str);
        }
      }      
    }
  }

  /**
   * Simple lock container that keeps a reference count.
   */
  @ThreadSafe
  private final class CountingLock {

    private final Object lock;
    @GuardedBy("this") private int refcount;

    /**
     * Initializes a Filelock with a refcount of 0.
     */
    public CountingLock() {
      lock = new Object();
      refcount = 0;
    }

    /**
     * Returns the locking object for this and increments refcount.
     */
    public synchronized Object getLock() {
      refcount++;
      return lock;
    }

    /**
     * Decrements refcount and returns the resulting count.
     */
    public synchronized int release() {
      return --refcount;
    }

  }

}
