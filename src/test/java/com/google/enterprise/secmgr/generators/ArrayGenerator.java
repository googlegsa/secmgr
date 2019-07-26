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

import java.util.Arrays;

/**
 * A generator that generates some given elements, which are supplied as an
 * array.  This generator's iterator returns the array's elements one at a time,
 * starting with the zero index and counting up.
 */
final class ArrayGenerator implements Generator {
  private static final Generator EMPTY = new ArrayGenerator(new Object[0]);
  private final Object[] objects;

  private ArrayGenerator(Object[] objects) {
    this.objects = objects;
  }

  static Generator make(Object... objects) {
    return (objects.length > 0)
        ? new ArrayGenerator(Arrays.copyOf(objects, objects.length))
        : EMPTY;
  }

  @Override
  public Generator.Iterator iterator() {
    return new LocalIterator(objects);
  }

  private static final class LocalIterator extends Generator.Iterator {
    private final Object[] objects;
    private int index;

    public LocalIterator(Object[] objects) {
      this.objects = objects;
      index = 0;
    }

    @Override
    public boolean hasNext() {
      return index < objects.length;
    }

    @Override
    public Object next() {
      Preconditions.checkState(hasNext());
      return objects[index++];
    }

    @Override
    public Object peek() {
      Preconditions.checkState(hasNext());
      return objects[index];
    }
  }
}
