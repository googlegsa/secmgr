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
 * A generator that combines the elements of a set of input generators.  This
 * works exactly like {@link CrossProductGenerator} except that a
 * <code>null</code> value in an input stream is dropped from the result.  The
 * elements of the output sequence of this generator are arrays, but unlike the
 * elements from a cross-product generator, these arrays may have fewer elements
 * than the number of input generators.
 * <p>
 * Basically this is useful for building up output sequences by doing cross
 * products, but where the arity of the output element is unimportant.  The
 * output element is just a sequence of input elements that preserves order.
 */
final class JoiningGenerator implements Generator {
  private final Generator[] generators;

  private JoiningGenerator(Generator[] generators) {
    this.generators = generators;
  }

  /**
   * Makes a joining generator.
   *
   * @param generators The generators providing the sequences to join.
   * @return A joining generator for the given input generators.
   */
  static Generator make(Generator... generators) {
    for (Generator generator : generators) {
      Preconditions.checkNotNull(generator);
    }
    switch (generators.length) {
      case 0: return Generators.of();
      case 1: return generators[0];
      default: return new JoiningGenerator(generators);
    }
  }

  @Override
  public Generator.Iterator iterator() {
    return new LocalIterator(generators);
  }

  private static final class LocalIterator extends CrossProductGenerator.LocalIterator {

    public LocalIterator(Generator[] generators) {
      super(generators);
    }

    @Override
    public Object peek() {
      int nResults = 0;
      for (Generator.Iterator iterator : iterators) {
        if (iterator.peek() != null) {
          nResults += 1;
        }
      }
      if (nResults == 0) {
        return null;
      }
      if (nResults == 1) {
        for (Generator.Iterator iterator : iterators) {
          Object object = iterator.peek();
          if (object != null) {
            return object;
          }
        }
      }
      Object[] results = new Object[nResults];
      int j = 0;
      for (Generator.Iterator iterator : iterators) {
        Object object = iterator.peek();
        if (object != null) {
          results[j++] = object;
        }
      }
      return results;
    }
  }
}
