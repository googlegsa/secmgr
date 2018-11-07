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

package com.google.enterprise.secmgr.generators;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.PeekingIterator;

import java.util.List;

/**
 * A generator that generates a sequence of elements that are supplied as a
 * list.  This basically enhances the {@link List} type to have a {@link
 * PeekingIterator} rather than an {@link java.util.Iterator}.
 */
final class ListGenerator implements Generator {
  private static final Generator EMPTY = new ListGenerator(ImmutableList.of());
  private final List<Object> objects;

  private ListGenerator(List<Object> objects) {
    this.objects = objects;
  }

  static Generator make(Iterable<? extends Object> iterable) {
    List<Object> objects = Lists.newArrayList(iterable);
    return (objects.size() > 0)
        ? new ListGenerator(objects)
        : EMPTY;
  }

  @Override
  public Generator.Iterator iterator() {
    return new LocalIterator(objects);
  }

  private static final class LocalIterator extends Generator.Iterator {
    private final java.util.Iterator<Object> iter;
    private boolean lookaheadOk;
    private Object lookahead;

    public LocalIterator(List<Object> objects) {
      iter = objects.iterator();
      step();
    }

    private void step() {
      lookaheadOk = iter.hasNext();
      if (lookaheadOk) {
        lookahead = iter.next();
      }
    }

    @Override
    public boolean hasNext() {
      return lookaheadOk;
    }

    @Override
    public Object next() {
      Preconditions.checkState(hasNext());
      Object result = lookahead;
      step();
      return result;
    }

    @Override
    public Object peek() {
      Preconditions.checkState(hasNext());
      return lookahead;
    }
  }
}
