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

package com.google.enterprise.secmgr.testing;

import com.google.common.base.Preconditions;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.concurrent.Callable;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import junit.framework.AssertionFailedError;

/**
 * A runnable test for methods.  Tests the method by calling it with a given
 * argument, then delegating to an {@link Expectation} to generate the test
 * result.
 *
 * @param <T> The type returned by the method.
 */
@Immutable
@ParametersAreNonnullByDefault
public class MethodTest<T> extends CallableTest<T> {
  @Nonnull protected final Class<T> valueClass;
  @Nonnull protected final Method method;
  @Nullable protected final Object object;
  @Nonnull protected final Object[] arguments;

  protected MethodTest(final Class<T> valueClass, Expectation<T> expectation, final Method method,
      @Nullable final Object object, final Object[] arguments) {
    super(
        new Callable<T>() {
          @Override
          public T call()
              throws Exception {
            return invokeMethod(valueClass, method, object, arguments);
          }
        },
        expectation);
    Preconditions.checkNotNull(valueClass);
    Preconditions.checkNotNull(method);
    Preconditions.checkNotNull(arguments);
    this.valueClass = valueClass;
    this.method = method;
    this.object = object;
    this.arguments = arguments;
  }

  /**
   * Makes a new runnable test for a given method and arguments.
   *
   * @param <V> The class of {@code method}'s value.
   * @param valueClass The class object corresponding to {@code <V>}.
   * @param expectation The expected behavior of the method.
   * @param method The method to be tested.
   * @param object The object to run the method on, or {@code null} for a static
   *     method.
   * @param arguments The arguments to test the method with.
   */
  @Nonnull
  public static <V> MethodTest<V> make(Class<V> valueClass, Expectation<V> expectation,
      Method method, @Nullable Object object, Object... arguments) {
    return new MethodTest<V>(valueClass, expectation, method, object, arguments);
  }

  /**
   * Gets the class of the method's value.
   */
  @Nonnull
  public Class<T> getValueClass() {
    return valueClass;
  }

  /**
   * Gets the method being tested.
   */
  @Nonnull
  public Method getMethod() {
    return method;
  }

  /**
   * Gets the object to invoke the method on.
   */
  @Nullable
  public Object getObject() {
    return object;
  }

  /**
   * Gets the arguments that will be passed to the method during the test.
   */
  @Nonnull
  public Object[] getArguments() {
    return arguments;
  }

  /**
   * Gets a method, catching exceptions and re-throwing them as assertion failures.
   */
  @Nonnull
  public static Method getMethod(Class<?> clazz, String name, Class<?>... parameterTypes) {
    try {
      return clazz.getMethod(name, parameterTypes);
    } catch (SecurityException e) {
      throw makeFailure("Exception while getting method: ", e);
    } catch (NoSuchMethodException e) {
      throw makeFailure("Exception while getting method: ", e);
    }
  }

  /**
   * Gets a static method, catching exceptions and re-throwing them as assertion failures.
   */
  @Nonnull
  public static Method getStaticMethod(Class<?> clazz, String name,
      Class<?>... parameterTypes) {
    Method method = getMethod(clazz, name, parameterTypes);
    if (!Modifier.isStatic(method.getModifiers())) {
      throw new AssertionFailedError("Not a static method: " + name);
    }
    return method;
  }

  /**
   * Invokes a given method with some arguments and returns its value.
   * Translates reflected exceptions to their cause.
   *
   * @param valueType The type of {@code method}'s returned value.
   * @param method The method to invoke.
   * @param instance The instance on which the method should be invoked, of
   *     {@code null} for a static method.
   * @param arguments The arguments to pass to {@code method}.
   * @return The value returned from the method.
   * @throws Exception if the method throws an exception, or if there's an
   *     access-control error when invoking the method.
   */
  @Nullable
  public static <T> T invokeMethod(Class<T> valueType, Method method,
      @Nullable Object instance, Object... arguments)
      throws Exception {
    try {
      return valueType.cast(method.invoke(instance, arguments));
    } catch (InvocationTargetException e) {
      Throwable t = e.getCause();
      if (t instanceof Exception) {
        throw (Exception) t;
      }
      throw makeFailure("Unexpected throwable: ", t);
    } catch (IllegalAccessException e) {
      throw makeFailure("Access exception: ", e);
    }
  }

  private static AssertionFailedError makeFailure(String message, Throwable e) {
    AssertionFailedError t = new AssertionFailedError(message);
    t.initCause(e);
    return t;
  }
}
