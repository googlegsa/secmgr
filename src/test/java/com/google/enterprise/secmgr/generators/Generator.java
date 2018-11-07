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

import com.google.common.collect.PeekingIterator;

/**
 * A generator is an Iterable<Object> with some special properties.  First, the
 * {@link Generator#iterator} method can be called multiple times and is
 * guaranteed to provide a new iterator each time.  Second, the returned
 * iterator is a {@link PeekingIterator}, which is slightly more useful than the
 * standard {@link Iterator} type.
 * <p>
 * We say that a generator "generates" some elements, which is shorthand for
 * saying that an iterator for the generator returns those elements one at a
 * time.  The elements returned by the iterator are called a "sequence" or
 * "generated sequence", and the generator is said to "generate a sequence".
 */
public interface Generator extends Iterable<Object> {

  /**
   * Get an iterator for this generator.  Each call to this method returns a new
   * iterator that starts iterating from the first object in the generator.
   *
   * @return A new iterator.
   */
  public Generator.Iterator iterator();

  /**
   * A generator's iterator type.  Provides the {@link PeekingIterator#peek}
   * method.
   */
  public abstract static class Iterator implements PeekingIterator<Object> {

    /**
     * A default implementation of {@link PeekingIterator#remove} that signals
     * {@link UnsupportedOperationException}.  At present, no generator provides
     * a working remove method.
     */
    public void remove() {
      throw new UnsupportedOperationException();
    }
  }
}
