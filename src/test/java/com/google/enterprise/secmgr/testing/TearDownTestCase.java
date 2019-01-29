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
package com.google.enterprise.secmgr.testing;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.collect.Lists;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.concurrent.GuardedBy;
import junit.framework.TestCase;

public abstract class TearDownTestCase extends TestCase {
  /** Creates a TearDownTestCase with the default (empty) name. */
  public TearDownTestCase() {}

  /** Creates a TearDownTestCase with the specified name. */
  public TearDownTestCase(String name) {
    super(name);
  }

  @Override
  protected void setUp() throws Exception {
    super.setUp();
  }

  final TearDownStack stack = new TearDownStack(true);

  /** Registers a TearDown implementor which will be run during {@link #tearDown()} */
  public final void addTearDown(TearDown tearDown) {
    stack.addTearDown(tearDown);
  }

  @Override
  protected void tearDown() {
    stack.runTearDown();
  }

  // Override to run setUp() inside the try block, not outside
  @Override
  public final void runBare() throws Throwable {
    try {
      setUp();
      runTest();
    } finally {
      tearDown();
    }
  }

  public interface TearDown {
    /**
     * Performs a <b>single</b> tear-down operation.
     *
     * @throws Exception for any reason. {@code TearDownTestCase} ensures that any exception thrown
     *     will not interfere with other TearDown operations.
     */
    void tearDown() throws Exception;
  }

  public interface TearDownAccepter {
    /**
     * Registers a TearDown implementor which will be run after the test proper.
     *
     * <p>In JUnit4 language, that means as an {@code @After}.
     *
     * <p>In JUnit3 language, that means during the {@link junit.framework.TestCase#tearDown()}
     * step.
     */
    void addTearDown(TearDown tearDown);
  }

  public static class TearDownStack implements TearDownAccepter {
    private static final Logger logger = Logger.getLogger(TearDownStack.class.getName());

    @GuardedBy("stack")
    final LinkedList<TearDown> stack = new LinkedList<>();

    private final boolean suppressThrows;

    public TearDownStack() {
      this.suppressThrows = false;
    }

    public TearDownStack(boolean suppressThrows) {
      this.suppressThrows = suppressThrows;
    }

    @Override
    public final void addTearDown(TearDown tearDown) {
      synchronized (stack) {
        stack.addFirst(checkNotNull(tearDown));
      }
    }

    /** Causes teardown to execute. */
    public final void runTearDown() {
      List<Throwable> exceptions = new ArrayList<>();
      List<TearDown> stackCopy;
      synchronized (stack) {
        stackCopy = Lists.newArrayList(stack);
        stack.clear();
      }
      for (TearDown tearDown : stackCopy) {
        try {
          tearDown.tearDown();
        } catch (Throwable t) {
          if (suppressThrows) {
            logger.log(Level.INFO, "exception thrown during tearDown", t);
          } else {
            exceptions.add(t);
          }
        }
      }
      if ((!suppressThrows) && (exceptions.size() > 0)) {
        throw ClusterException.create(exceptions);
      }
    }
  }

  static final class ClusterException extends RuntimeException {

    public final Collection<? extends Throwable> exceptions;

    private ClusterException(Collection<? extends Throwable> exceptions) {
      super(
          exceptions.size() + " exceptions were thrown. The first exception is listed as a cause.",
          exceptions.iterator().next());
      ArrayList<Throwable> temp = new ArrayList<>();
      temp.addAll(exceptions);
      this.exceptions = Collections.unmodifiableCollection(temp);
    }

    /** @see #create(Collection) */
    public static RuntimeException create(Throwable... exceptions) {
      ArrayList<Throwable> temp = new ArrayList<>(Arrays.asList(exceptions));
      return create(temp);
    }

    /**
     * Given a collection of exceptions, returns a {@link RuntimeException}, with the following
     * rules:
     *
     * <ul>
     *   <li>If {@code exceptions} has a single exception and that exception is a {@link
     *       RuntimeException}, return it
     *   <li>If {@code exceptions} has a single exceptions and that exceptions is <em>not</em> a
     *       {@link RuntimeException}, return a simple {@code RuntimeException} that wraps it
     *   <li>Otherwise, return an instance of {@link ClusterException} that wraps the first
     *       exception in the {@code exceptions} collection.
     * </ul>
     *
     * <p>Though this method takes any {@link Collection}, it often makes most sense to pass a
     * {@link java.util.List} or some other collection that preserves the order in which the
     * exceptions got added.
     *
     * @throws NullPointerException if {@code exceptions} is null
     * @throws IllegalArgumentException if {@code exceptions} is empty
     */
    public static RuntimeException create(Collection<? extends Throwable> exceptions) {
      if (exceptions.size() == 0) {
        throw new IllegalArgumentException(
            "Can't create an ExceptionCollection with no exceptions");
      }
      if (exceptions.size() == 1) {
        Throwable temp = exceptions.iterator().next();
        if (temp instanceof RuntimeException) {
          return (RuntimeException) temp;
        } else {
          return new RuntimeException(temp);
        }
      }
      return new ClusterException(exceptions);
    }
  }
}
