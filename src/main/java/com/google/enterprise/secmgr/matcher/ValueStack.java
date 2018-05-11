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
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;

import java.util.Deque;
import java.util.Iterator;
import java.util.NoSuchElementException;

import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * An implementation of a stack for holding values generated during the matching
 * process.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
public abstract class ValueStack implements Iterable<Object> {
  /**
   * Is the stack empty?
   */
  public abstract boolean isEmpty();

  /**
   * Gets the number of values pushed on the stack.
   */
  @Nonnegative
  public abstract int size();

  /**
   * Pushes a value on the stack.
   *
   * @param value The value to be pushed.
   * @return A new stack on which the given value has been pushed.
   */
  @Nonnull
  public abstract ValueStack push(Object value);

  /**
   * Gets the value at the top of the stack.
   *
   * @throws NoSuchElementException if the stack is empty.
   */
  @Nonnull
  public abstract Object top();

  /**
   * Pops a value off the stack.
   *
   * @return A new stack in which the top-most value has been removed.
   * @throws NoSuchElementException if the stack is empty.
   */
  @Nonnull
  public abstract ValueStack pop();

  /**
   * Converts the stack to an immutable list.  The returned list starts with the
   * bottom-most value on the stack and ends with the top-most value.
   */
  @Nonnull
  public abstract ImmutableList<Object> toList();

  /**
   * Gets an iterator for the stack.  The stack's values are iterated starting
   * with the top-most value and proceeding to the bottom-most value.
   */
  @Override
  public Iterator<Object> iterator() {
    return new LocalIterator(this);
  }

  @Override
  public String toString() {
    return toList().toString();
  }

  /**
   * Gets an empty stack.
   */
  @Nonnull
  public static ValueStack empty() {
    return EMPTY;
  }

  private static final ValueStack EMPTY =
      new ValueStack() {
        @Override
        public boolean isEmpty() {
          return true;
        }

        @Override
        public int size() {
          return 0;
        }

        @Override
        public ValueStack push(Object value) {
          return NonEmpty.make(value, this);
        }

        @Override
        public Object top() {
          throw new NoSuchElementException();
        }

        @Override
        public ValueStack pop() {
          throw new NoSuchElementException();
        }

        @Override
        public ImmutableList<Object> toList() {
          return ImmutableList.of();
        }
      };

  private static final class NonEmpty extends ValueStack {
    @Nonnegative final int nValues;
    @Nonnull final Object value;
    @Nonnull final ValueStack rest;

    NonEmpty(@Nonnegative int nValues, Object value, ValueStack rest) {
      this.nValues = nValues;
      this.value = value;
      this.rest = rest;
    }

    @Nonnull
    static ValueStack make(Object value, ValueStack rest) {
      Preconditions.checkNotNull(value);
      return new NonEmpty(rest.size() + 1, value, rest);
    }

    @Override
    public boolean isEmpty() {
      return false;
    }

    @Override
    public int size() {
      return nValues;
    }

    @Override
    public ValueStack push(Object value) {
      return make(value, this);
    }

    @Override
    public Object top() {
      return value;
    }

    @Override
    public ValueStack pop() {
      return rest;
    }

    @Override
    public ImmutableList<Object> toList() {
      Deque<Object> deque = Lists.newLinkedList();
      for (Object value : this) {
        deque.addFirst(value);
      }
      return ImmutableList.copyOf(deque);
    }
  }

  @NotThreadSafe
  private static final class LocalIterator implements Iterator<Object> {
    ValueStack stack;

    LocalIterator(ValueStack stack) {
      this.stack = stack;
    }

    @Override
    public boolean hasNext() {
      return !stack.isEmpty();
    }

    @Override
    public Object next() {
      if (stack.isEmpty()) { throw new NoSuchElementException(); }
      Object value = stack.top();
      stack = stack.pop();
      return value;
    }

    @Override
    public void remove() {
      throw new UnsupportedOperationException();
    }
  }
}
