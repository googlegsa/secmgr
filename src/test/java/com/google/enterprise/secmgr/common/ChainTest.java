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

package com.google.enterprise.secmgr.common;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.testing.CallableTest;
import com.google.enterprise.secmgr.testing.EqualValueExpectation;
import com.google.enterprise.secmgr.testing.Expectation;
import com.google.enterprise.secmgr.testing.FunctionTest;
import com.google.enterprise.secmgr.testing.IdenticalValueExpectation;
import com.google.enterprise.secmgr.testing.RunnableTest;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.enterprise.secmgr.testing.SimpleExceptionExpectation;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.Callable;

/**
 * Unit tests for {@link Chain}.
 */
public class ChainTest extends SecurityManagerTestCase {
  private static final String A = "A";
  private static final String B = "B";

  private final Chain<String> chain1 = Chain.empty();
  private final Chain<String> chain2 = chain1.add(A);
  private final Chain<String> chain3 = chain2.add(B);
  private final Chain<String> chain4 = chain1.add(B);
  private final Chain<String> chain5 = chain4.add(A);

  private final String[] array1 = new String[] {};
  private final String[] array2 = new String[] { A };
  private final String[] array3 = new String[] { A, B };
  private final String[] array4 = new String[] { B };
  private final String[] array5 = new String[] { B, A };

  private final List<Chain<String>> chains =
      ImmutableList.of(chain1, chain2, chain3, chain4, chain5);
  @SuppressWarnings("unchecked")
  private final List<Chain<String>> rests =
      Lists.newArrayList(null, chain1, chain2, chain1, chain4);
  private final List<String[]> arrays =
      ImmutableList.of(array1, array2, array3, array4, array5);
  private final List<Chain<String>> altChains =
      ImmutableList.copyOf(
          Iterables.transform(arrays,
              new Function<String[], Chain<String>>() {
                @Override
                public Chain<String> apply(String[] array) {
                  return makeChain(array);
                }
              }));

  public void testBasic() {
    for (Chain<String> c1 : chains) {
      for (Chain<String> c2 : chains) {
        if (c1 == c2) {
          assertEquals(c1, c2);
        } else {
          assertFalse(c1.equals(c2));
        }
      }
    }

    List<RunnableTest> tests = Lists.newArrayList();
    for (int i = 0; i < chains.size(); i += 1) {
      assertEquals(chains.get(i), altChains.get(i));
      assertEquals(chains.get(i).hashCode(), altChains.get(i).hashCode());
      addBasicTests(tests, chains.get(i), rests.get(i), arrays.get(i));
    }
    runTests(tests);
  }

  private void addBasicTests(List<RunnableTest> tests, Chain<String> chain, Chain<String> rest,
      String... elements) {
    tests.add(
        CallableTest.make(makeSizeCallable(chain), EqualValueExpectation.make(elements.length)));

    tests.add(
        CallableTest.make(makeIsEmptyCallable(chain),
            EqualValueExpectation.make(elements.length == 0)));

    tests.add(
        CallableTest.make(makeGetLastCallable(chain),
            (elements.length == 0)
            ? badGetLastExpectation
            : EqualValueExpectation.make(elements[elements.length - 1])));

    tests.add(
        CallableTest.make(makeGetRestCallable(chain),
            (rest == null)
            ? badGetRestExpectation
            : IdenticalValueExpectation.make(rest)));

    Function<Integer, String> function = makeGetFunction(chain);

    for (int i = 0; i < elements.length; i += 1) {
      tests.add(FunctionTest.make(function, i, EqualValueExpectation.make(elements[i])));
    }

    tests.add(FunctionTest.make(function, Integer.valueOf(-1), badGetExpectation));
    tests.add(FunctionTest.make(function, Integer.valueOf(elements.length), badGetExpectation));
  }

  public void testToList() {
    List<RunnableTest> tests = Lists.newArrayList();
    for (int i = 0; i < chains.size(); i += 1) {
      addToListTests(tests, chains.get(i), arrays.get(i));
    }
    runTests(tests);
  }

  private void addToListTests(List<RunnableTest> tests, Chain<String> chain, String... elements) {

    List<String> fullValue = ImmutableList.copyOf(elements);

    tests.add(
        CallableTest.make(makeToListCallable(chain), EqualValueExpectation.make(fullValue)));

    Function<Chain<String>, List<String>> function = makeToListFunction(chain);

    Chain<String> ancestor = chain;
    int i = elements.length;
    while (true) {
      tests.add(
          FunctionTest.make(function, ancestor,
              EqualValueExpectation.make(fullValue.subList(i, elements.length))));
      if (ancestor.isEmpty()) {
        break;
      }
      ancestor = ancestor.getRest();
      i -= 1;
    }

    tests.add(FunctionTest.make(function, null, badToListExpectation));
  }

  private Chain<String> makeChain(String... elements) {
    Chain<String> c = Chain.empty();
    for (String element : elements) {
      c = c.add(element);
    }
    return c;
  }

  private static Callable<Integer> makeSizeCallable(final Chain<String> chain) {
    return new Callable<Integer>() {
      @Override
      public Integer call() {
        return chain.size();
      }
    };
  }

  private static Callable<Boolean> makeIsEmptyCallable(final Chain<String> chain) {
    return new Callable<Boolean>() {
      @Override
      public Boolean call() {
        return chain.isEmpty();
      }
    };
  }

  private static Callable<String> makeGetLastCallable(final Chain<String> chain) {
    return new Callable<String>() {
      @Override
      public String call()
          throws NoSuchElementException {
        return chain.getLast();
      }
    };
  }

  private static Callable<Chain<String>> makeGetRestCallable(final Chain<String> chain) {
    return new Callable<Chain<String>>() {
      @Override
      public Chain<String> call()
          throws NoSuchElementException {
        return chain.getRest();
      }
    };
  }

  private static Function<Integer, String> makeGetFunction(final Chain<String> chain) {
    return new Function<Integer, String>() {
      @Override
      public String apply(Integer index) {
        return chain.get(index);
      }
    };
  }

  private static Function<Chain<String>, List<String>> makeToListFunction(
      final Chain<String> chain) {
    return new Function<Chain<String>, List<String>>() {
      @Override
      public List<String> apply(Chain<String> ancestor) {
        return chain.toList(ancestor);
      }
    };
  }

  private static Callable<List<String>> makeToListCallable(final Chain<String> chain) {
    return new Callable<List<String>>() {
      @Override
      public List<String> call() {
        return chain.toList();
      }
    };
  }

  private static Expectation<String> badGetExpectation =
      SimpleExceptionExpectation.make(IllegalArgumentException.class);

  private static Expectation<String> badGetLastExpectation =
      SimpleExceptionExpectation.make(UnsupportedOperationException.class);

  private static Expectation<Chain<String>> badGetRestExpectation =
      SimpleExceptionExpectation.make(UnsupportedOperationException.class);

  private static Expectation<List<String>> badToListExpectation =
      SimpleExceptionExpectation.make(NullPointerException.class);
}
