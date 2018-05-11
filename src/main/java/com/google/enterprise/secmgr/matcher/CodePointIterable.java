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
package com.google.enterprise.secmgr.matcher;

import com.google.common.collect.AbstractIterator;

import java.util.Iterator;

/**
 * Provides iterators over the Unicode code points of a string.
 * Surrogates pairs consist of two Java {@code char} values.
 * <p>
 * Preferred over iterating over <code>char</code> to handle characters outside
 * the Basic Multilingual Plan, which use Surrogate pairs.
 */
class CodePointIterable implements Iterable<Integer> {

  private final CharSequence seq;

  /**
   * Create a new Iterable that can iterate over a sequence of code points
   *
   * @param seq a sequence of <code>char</code> values (Unicode code units)
   */
  CodePointIterable(CharSequence seq) {
    this.seq = seq;
  }

  @Override
  public Iterator<Integer> iterator() {
    return new CodePointIterator();
  }

  private class CodePointIterator extends AbstractIterator<Integer> {

    private int index;

    @Override protected Integer computeNext() {
      if (index < seq.length()) {
        int codePoint = Character.codePointAt(seq, index);
        // increment by the codePoint width
        index += Character.charCount(codePoint);
        return codePoint;
      } else {
        return endOfData();
      }
    }
  }
}
