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

/**
 * This is a generator that concatenates the output from some given generators.
 * That is, the output sequence of this generator consists of the output
 * sequence of the first input generator, followed by the output sequence of the
 * second input generator, and so on.
 */
final class GeneratorConcatenator implements Generator {
  private final Generator[] generators;

  private GeneratorConcatenator(Generator[] generators) {
    this.generators = generators;
  }

  static Generator make(Generator... generators) {
    for (Generator generator : generators) {
      Preconditions.checkNotNull(generator);
    }
    switch (generators.length) {
      case 0: return Generators.of();
      case 1: return generators[0];
      default: return new GeneratorConcatenator(generators);
    }
  }

  @Override
  public Generator.Iterator iterator() {
    return new LocalIterator(generators);
  }

  private static class LocalIterator extends Generator.Iterator {
    private final Generator[] generators;
    private Generator.Iterator iter;
    private int index;

    public LocalIterator(Generator[] generators) {
      this.generators = generators;
      if (generators.length > 0) {
        iter = generators[0].iterator();
        index = 1;
      } else {
        iter = null;
      }
    }

    @Override
    public boolean hasNext() {
      if (iter == null) {
        return false;
      }
      while (true) {
        if (iter.hasNext()) {
          return true;
        }
        if (index >= generators.length) {
          iter = null;
          return false;
        }
        iter = generators[index++].iterator();
      }
    }

    @Override
    public Object next() {
      return iter.next();
    }

    @Override
    public Object peek() {
      return iter.peek();
    }
  }
}
