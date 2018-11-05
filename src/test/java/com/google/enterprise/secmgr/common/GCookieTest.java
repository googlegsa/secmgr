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
import com.google.common.base.Functions;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.generators.Generator;
import com.google.enterprise.secmgr.generators.Generators;
import com.google.enterprise.secmgr.testing.AbstractValueExpectation;
import com.google.enterprise.secmgr.testing.CallableTest;
import com.google.enterprise.secmgr.testing.EqualValueExpectation;
import com.google.enterprise.secmgr.testing.Expectation;
import com.google.enterprise.secmgr.testing.FunctionTest;
import com.google.enterprise.secmgr.testing.MethodTest;
import com.google.enterprise.secmgr.testing.RunnableTest;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.enterprise.secmgr.testing.SimpleExceptionExpectation;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import javax.servlet.http.Cookie;
import org.joda.time.DateTimeUtils;

/**
 * Tests for the {@link GCookie} class.
 */
public final class GCookieTest extends SecurityManagerTestCase {

  // **************** The tests ****************

  public void testIsCookieName() {
    List<RunnableTest> tests = Lists.newArrayList();
    Method method = MethodTest.getStaticMethod(GCookie.class, "isCookieName", String.class);
    for (String name : GOOD_NAME) {
      tests.add(MethodTest.make(Boolean.class, TRUE_VALUE, method, null, name));
    }
    for (String name : BAD_NAME) {
      tests.add(MethodTest.make(Boolean.class, FALSE_VALUE, method, null, name));
    }
    tests.add(
        MethodTest.make(Boolean.class,
            SimpleExceptionExpectation.<Boolean>make(NullPointerException.class),
            method, null, (Object) null));
    runTests(tests);
  }

  public void testIsCookieValue() {
    List<RunnableTest> tests = Lists.newArrayList();
    Method method = MethodTest.getStaticMethod(GCookie.class, "isCookieValue", String.class);
    for (String value : GOOD_VALUE) {
      tests.add(MethodTest.make(Boolean.class, TRUE_VALUE, method, null, value));
    }
    for (String value : BAD_VALUE) {
      tests.add(MethodTest.make(Boolean.class, FALSE_VALUE, method, null, value));
    }
    tests.add(MethodTest.make(Boolean.class,
            SimpleExceptionExpectation.<Boolean>make(NullPointerException.class),
            method, null, (Object) null));
    runTests(tests);
  }

  public void testBuilder() {
    List<RunnableTest> tests = Lists.newArrayList();
    Function<String, GCookie> function = new Function<String, GCookie>() {
      @Override
      public GCookie apply(String name) {
        return GCookie.builder(name).build();
      }
    };
    for (String name : GOOD_NAME) {
      tests.add(
          FunctionTest.make(function, name,
              new GCookieExpectation<String>("getName", name, STRING_CAST)));
    }
    for (String name : BAD_NAME) {
      tests.add(FunctionTest.make(function, name, ILLEGAL_ARGUMENT));
    }
    runTests(tests);
  }

  public void testMake() {
    List<RunnableTest> tests = Lists.newArrayList();
    Generator genGoodName = Generators.of((Object[]) GOOD_NAME);
    Generator genBadName = Generators.of((Object[]) BAD_NAME);
    Generator genGoodValue = Generators.of((Object[]) GOOD_VALUE);
    Generator genBadValue = Generators.of((Object[]) BAD_VALUE);
    Method method = MethodTest.getStaticMethod(GCookie.class, "make", String.class, String.class);
    for (Object[] args : Generators.crossProductIterable(genGoodName, genGoodValue)) {
      tests.add(
          MethodTest.make(GCookie.class,
              new GCookieExpectation<String>("getValue", args[1], STRING_CAST),
              method, null, args));
    }
    for (Object[] args : Generators.crossProductIterable(genBadName, genGoodValue)) {
      tests.add(MethodTest.make(GCookie.class, ILLEGAL_ARGUMENT, method, null, args));
    }
    for (Object[] args : Generators.crossProductIterable(genGoodName, genBadValue)) {
      tests.add(MethodTest.make(GCookie.class, ILLEGAL_ARGUMENT, method, null, args));
    }
    for (Object[] args : Generators.crossProductIterable(genBadName, genBadValue)) {
      tests.add(MethodTest.make(GCookie.class, ILLEGAL_ARGUMENT, method, null, args));
    }
    runTests(tests);
  }

  public void testSetValue() {
    tryStringSetter("Value", GOOD_VALUE, BAD_VALUE);
  }

  public void testSetExpires() {
    tryLongSetter("Expires", GOOD_EXPIRES, BAD_EXPIRES);
  }

  public void testSetDomain() {
    tryStringSetter("Domain", GOOD_DOMAIN, BAD_DOMAIN,
        new Function<String, String>() {
          @Override
          public String apply(String value) {
            return normalizeDomain(value);
          }
        });
  }

  private static String normalizeDomain(String domain) {
    return (domain.startsWith(".") ? domain.substring(1) : domain).toLowerCase();
  }

  public void testSetPath() {
    tryStringSetter("Path", GOOD_PATH, BAD_PATH);
  }

  public void testSetCreationTime() {
    tryLongSetter("CreationTime", GOOD_TIMES, BAD_TIMES);
  }

  public void testSetLastAccessTime() {
    tryLongSetter("LastAccessTime", GOOD_TIMES, BAD_TIMES);
  }

  public void testSetPersistent() {
    tryBooleanSetter("Persistent");
  }

  public void testSetSecureOnly() {
    tryBooleanSetter("SecureOnly");
  }

  public void testSetHostOnly() {
    tryBooleanSetter("HostOnly");
  }

  public void testSetHttpOnly() {
    tryBooleanSetter("HttpOnly");
  }

  public void testSetMaxAge() {
    trySetter("MaxAge", Long.TYPE, MAX_AGE_CAST, GOOD_MAX_AGE, null,
        new Function<Long, Long>() {
          @Override
          public Long apply(Long value) {
            return normalizeMaxAge(value);
          }
        });
  }

  private static final Function<Object, Long> MAX_AGE_CAST = new Function<Object, Long>() {
    @Override
    public Long apply(Object object) {
      if (object instanceof Long) {
        return (Long) object;
      }
      return Integer.class.cast(object).longValue();
    }
  };

  private static long normalizeMaxAge(long value) {
    return (value < 0) ? -1 : value;
  }

  public void testEquals() {
    List<GCookie> cookies1 = generateCookies(ALL_DESCRIPTIONS, GCOOKIE_BUILDER);
    List<GCookie> cookies2 = generateCookies(ALL_DESCRIPTIONS, GCOOKIE_BUILDER);
    assertEquals(cookies1, cookies2);
    for (int i = 0; i < cookies1.size(); i += 1) {
      GCookie c1 = cookies1.get(i);
      GCookie c2 = cookies2.get(i);
      assertEquals(expectedEqualsIgnoreCase(c1, c2), c1.hashCode() == c2.hashCode());
    }
  }

  public void testEqualsIgnoreCase() {
    List<GCookie> cookies1 = generateCookies(CASE_TEST_DESCRIPTIONS_1, GCOOKIE_BUILDER);
    List<GCookie> cookies2 = generateCookies(CASE_TEST_DESCRIPTIONS_2, GCOOKIE_BUILDER);
    assertEquals(cookies1.size(), cookies2.size());
    for (int i = 0; i < cookies1.size(); i += 1) {
      GCookie c1 = cookies1.get(i);
      GCookie c2 = cookies2.get(i);
      assertEquals(expectedEqualsIgnoreCase(c1, c2), c1.equals(c2));
      assertEquals(expectedEqualsIgnoreCase(c1, c2), c1.hashCode() == c2.hashCode());
    }
  }

  public void testHasSameKey() {
    List<GCookie> cookies1 = generateCookies(CASE_TEST_DESCRIPTIONS_1, GCOOKIE_BUILDER);
    List<GCookie> cookies2 = generateCookies(CASE_TEST_DESCRIPTIONS_2, GCOOKIE_BUILDER);
    assertEquals(cookies1.size(), cookies2.size());
    for (int i = 0; i < cookies1.size(); i += 1) {
      GCookie c1 = cookies1.get(i);
      GCookie c2 = cookies2.get(i);
      assertEquals(expectedHasSameName(c1, c2), c1.hasSameKey(c2));
    }
  }

  public void testCookieToGCookie() {
    List<Cookie> inputs = generateCookies(COOKIE_DESCRIPTIONS, COOKIE_BUILDER);
    List<GCookie> expecteds = generateCookies(COOKIE_DESCRIPTIONS, GCOOKIE_BUILDER);
    assertEquals(inputs.size(), expecteds.size());
    for (int i = 0; i < inputs.size(); i += 1) {
      Cookie input = inputs.get(i);
      GCookie expected = expecteds.get(i);
      GCookie actual = GCookie.fromCookie(input);
      assertEquals(expected, actual);
    }
  }

  public void testGCookieToGCookie() {
    for (GCookie c1 : generateCookies(ALL_DESCRIPTIONS, GCOOKIE_BUILDER)) {
      GCookie c2 = GCookie.builder(c1).build();
      assertEquals(c1, c2);
    }
  }

  public void testGCookieToCookie() {
    List<GCookie> inputs = generateCookies(COOKIE_DESCRIPTIONS, GCOOKIE_BUILDER);
    List<Cookie> expecteds = generateCookies(COOKIE_DESCRIPTIONS, COOKIE_BUILDER);
    assertEquals(inputs.size(), expecteds.size());
    for (int i = 0; i < inputs.size(); i += 1) {
      GCookie input = inputs.get(i);
      Cookie expected = expecteds.get(i);
      Cookie actual = input.toCookie();
      assertEqualCookies(expected, actual);
    }
  }

  public void testGCookiesToCookies() {
    List<GCookie> input = generateCookies(ALL_DESCRIPTIONS, GCOOKIE_BUILDER);
    List<Cookie> expected = generateCookies(ALL_DESCRIPTIONS, COOKIE_BUILDER);
    List<Cookie> actual = GCookie.toCookie(input);
    assertEquals(expected.size(), actual.size());
    for (int i = 0; i < expected.size(); i += 1) {
      assertEqualCookies(expected.get(i), actual.get(i));
    }
  }

  private void assertEqualCookies(Cookie expected, Cookie actual) {
    assertEquals(expected.getName(), actual.getName());
    assertEquals(expected.getValue(), actual.getValue());
    assertEquals(normalizeDomain(expected.getDomain()), actual.getDomain());
    assertEquals(expected.getPath(), actual.getPath());
    assertEquals(expected.getSecure(), actual.getSecure());
    assertEquals(normalizeMaxAge(expected.getMaxAge()), actual.getMaxAge());
  }

  // **************** Infrastructure to build cookies ****************

  private static <T> List<T> generateCookies(List<Description> descriptions,
      CookieBuilder<T> cookieBuilder) {
    ImmutableList.Builder<T> listBuilder = ImmutableList.builder();
    for (Description description : descriptions) {
      T cookie;
      try {
        cookie = cookieBuilder.apply(description);
      } catch (RuntimeException e) {
        continue;
      }
      listBuilder.add(cookie);
    }
    return listBuilder.build();
  }

  private static List<Description> deconstruct(Generator generator, Deconstructor deconstructor) {
    ImmutableList.Builder<Description> listBuilder = ImmutableList.builder();
    for (Object rawDescription : generator) {
      listBuilder.add(deconstructor.apply((Object[]) rawDescription));
    }
    return listBuilder.build();
  }

  private interface Deconstructor {
    public Description apply(Object[] rawDescription);
  }

  private interface CookieBuilder<T> {
    public T apply(Description description);
  }

  private static final class Description {
    final String name;
    final String value;
    final long expires;
    final String domain;
    final String path;
    final long creationTime;
    final long lastAccessTime;
    final boolean persistent;
    final boolean hostOnly;
    final boolean secureOnly;
    final boolean httpOnly;
    final Long maxAge;

    Description(String name, String value, long expires, String domain, String path,
        boolean persistent, boolean hostOnly, boolean secureOnly, boolean httpOnly,
        Long maxAge) {
      long now = DateTimeUtils.currentTimeMillis();
      this.name = name;
      this.value = value;
      this.expires = expires;
      this.domain = domain;
      this.path = path;
      this.creationTime = now;
      this.lastAccessTime = now;
      this.persistent = persistent;
      this.hostOnly = hostOnly;
      this.secureOnly = secureOnly;
      this.httpOnly = httpOnly;
      this.maxAge = maxAge;
    }

    int getMaxAge() {
      if (maxAge != null) {
        return maxAge.intValue();
      }
      if (!persistent) {
        return -1;
      }
      if (expires < creationTime) {
        return 0;
      }
      long deltaSeconds = ((expires - creationTime) + 500) / 1000;
      return (deltaSeconds > Integer.MAX_VALUE)
          ? -1
          : (int) deltaSeconds;
    }
  }

  private static final CookieBuilder<GCookie> GCOOKIE_BUILDER =
      new CookieBuilder<GCookie>() {
        @Override
        public GCookie apply(Description d) {
          GCookie.Builder builder
            = GCookie.builder(d.name)
              .setValue(d.value)
              .setExpires(d.expires)
              .setDomain(d.domain)
              .setPath(d.path)
              .setCreationTime(d.creationTime)
              .setLastAccessTime(d.lastAccessTime)
              .setPersistent(d.persistent)
              .setHostOnly(d.hostOnly)
              .setSecureOnly(d.secureOnly)
              .setHttpOnly(d.httpOnly);
          if (d.maxAge != null) {
            builder.setMaxAge(d.maxAge);
          }
          return builder.build();
        }
      };

  private static final CookieBuilder<Cookie> COOKIE_BUILDER =
      new CookieBuilder<Cookie>() {
        @Override
        public Cookie apply(Description d) {
          Cookie cookie = new Cookie(d.name, d.value);
          if (d.domain != null) {
            cookie.setDomain(d.domain);
          }
          cookie.setPath(d.path);
          cookie.setSecure(d.secureOnly);
          cookie.setMaxAge(d.getMaxAge());
          return cookie;
        }
      };

  // **************** The elements used to make cookie descriptions ****************

  private static final String[] GOOD_NAME = {
    "name1", "name$", "$Version"
  };

  private static final String[] BAD_NAME = {
    "", "=", "f=ma", ";", "foo;bar"
  };

  private static final String[] GOOD_LEGACY_NAME = {
    "name1", "name$"
  };

  private static final String[] NAME_CASE_1 = {
    "name1", "Name2", "NAME3", "naMe4"
  };

  private static final String[] NAME_CASE_2 = {
    "naMe1", "NAME2", "Name3", "name4"
  };

  private static final String[] GOOD_VALUE = {
    "", "value1", "value 3", "\n", "\r", "\0", "foo=bar"
  };
  private static final String[] RESTRICTED_GOOD_VALUE = Arrays.copyOf(GOOD_VALUE, 3);

  private static final String[] BAD_VALUE = {
    ";", "foo;bar"
  };

  private static final String[] VALUE_CASE_1 = {
    "value1", "Value2", "VALUE3", "vaLue4"
  };

  private static final String[] VALUE_CASE_2 = {
    "vaLue1", "VALUE2", "Value3", "value4"
  };

  private static final String[] GOOD_DOMAIN = {
    "", "example.com", ".example.com", "localhost"
  };

  private static final String[] BAD_DOMAIN = {
    // Re-enable if we add support for public suffixes.
    //"com"
  };

  private static final String[] DOMAIN_CASE_1 = {
    ".domain1.com", ".Domain2.Org", ".DOMAIN3.NET", ".domAIN4.eDu"
  };

  private static final String[] DOMAIN_CASE_2 = {
    ".domAIN1.cOm", ".DOMAIN2.ORG", ".Domain3.Net", ".domain4.edu"
  };

  private static final String[] GOOD_PATH = {
    "", "/", "/foo", "/foo/bar"
  };

  private static final String[] BAD_PATH = {
    "foo", "foo/", "foo/bar"
  };

  private static final String[] PATH_CASE_1 = {
    "/path1/foo", "/Path2/Bar", "/PATH3/BAZ", "/paTH4/muMBle"
  };

  private static final String[] PATH_CASE_2 = {
    "/paTH1/fOo", "/PATH2/BAR", "/Path3/Baz", "/path4/mumble"
  };

  private static final Boolean[] GOOD_BOOLEAN = {
    false, true
  };

  private static final Long[] GOOD_MAX_AGE = {
    Long.valueOf(Integer.MIN_VALUE), -1L, 0L, 1L, Long.valueOf(Integer.MAX_VALUE)
  };

  private static final Long[] GOOD_EXPIRES = {
    0L, HttpUtil.parseHttpDate("Fri, 02 Jan 2009 15:00:00 GMT"), Long.MAX_VALUE
  };

  private static final Long[] BAD_EXPIRES = {
    -1L, Long.MIN_VALUE
  };

  private static final Long[] GOOD_TIMES = {
    0L, HttpUtil.parseHttpDate("Fri, 02 Jan 2009 15:00:00 GMT")
  };

  private static final Long[] BAD_TIMES = {
    -1L, Long.MIN_VALUE, Long.MAX_VALUE
  };

  // **************** Generate lots of cookie descriptions ****************

  private static final List<Description> ALL_DESCRIPTIONS =
      deconstruct(
          Generators.crossProduct(
              Generators.of((Object[]) GOOD_NAME),
              Generators.of((Object[]) RESTRICTED_GOOD_VALUE),
              Generators.of((Object[]) GOOD_EXPIRES),
              Generators.of((Object[]) GOOD_DOMAIN),
              Generators.of((Object[]) GOOD_PATH),
              Generators.of((Object[]) GOOD_BOOLEAN),  // persistent
              Generators.of((Object[]) GOOD_BOOLEAN),  // hostOnly
              Generators.of((Object[]) GOOD_BOOLEAN),  // secureOnly
              Generators.of((Object[]) GOOD_BOOLEAN)), // httpOnly
          new Deconstructor() {
            @Override
            public Description apply(Object[] description) {
              return new Description(
                  String.class.cast(description[0]),
                  String.class.cast(description[1]),
                  Long.class.cast(description[2]),
                  String.class.cast(description[3]),
                  String.class.cast(description[4]),
                  Boolean.class.cast(description[5]),
                  Boolean.class.cast(description[6]),
                  Boolean.class.cast(description[7]),
                  Boolean.class.cast(description[8]),
                  null);
            }
          });

  private static final List<Description> COOKIE_DESCRIPTIONS =
      deconstruct(
          Generators.crossProduct(
              Generators.of((Object[]) GOOD_LEGACY_NAME),
              Generators.of((Object[]) RESTRICTED_GOOD_VALUE),
              Generators.of((Object[]) GOOD_DOMAIN),
              Generators.of((Object[]) GOOD_PATH),
              Generators.of((Object[]) GOOD_BOOLEAN),  // Secure
              Generators.of((Object[]) GOOD_MAX_AGE)),
          new Deconstructor() {
            @Override
            public Description apply(Object[] description) {
              return new Description(
                  String.class.cast(description[0]),
                  String.class.cast(description[1]),
                  Long.MAX_VALUE,
                  String.class.cast(description[2]),
                  String.class.cast(description[3]),
                  false,
                  false,
                  Boolean.class.cast(description[4]),
                  false,
                  Long.class.cast(description[5]));
            }
          });

  private static final Deconstructor CASE_TEST_DECONSTRUCTOR =
      new Deconstructor() {
        @Override
        public Description apply(Object[] description) {
          return new Description(
              String.class.cast(description[0]),
              String.class.cast(description[1]),
              Long.MAX_VALUE,
              String.class.cast(description[2]),
              String.class.cast(description[3]),
              false,
              false,
              false,
              false,
              null);
        }
      };

  private static final List<Description> CASE_TEST_DESCRIPTIONS_1 =
      deconstruct(
          Generators.crossProduct(
              Generators.of((Object[]) NAME_CASE_1),
              Generators.of((Object[]) VALUE_CASE_1),
              Generators.of((Object[]) DOMAIN_CASE_1),
              Generators.of((Object[]) PATH_CASE_1)),
          CASE_TEST_DECONSTRUCTOR);

  private static final List<Description> CASE_TEST_DESCRIPTIONS_2 =
      deconstruct(
          Generators.crossProduct(
              Generators.of((Object[]) NAME_CASE_2),
              Generators.of((Object[]) VALUE_CASE_2),
              Generators.of((Object[]) DOMAIN_CASE_2),
              Generators.of((Object[]) PATH_CASE_2)),
          CASE_TEST_DECONSTRUCTOR);

  // **************** Expectations ****************

  private static final Expectation<Boolean> TRUE_VALUE =
      EqualValueExpectation.make(true);

  private static final Expectation<Boolean> FALSE_VALUE =
      EqualValueExpectation.make(false);

  private static final Expectation<GCookie> ILLEGAL_ARGUMENT =
      SimpleExceptionExpectation.make(IllegalArgumentException.class);

  private boolean expectedEqualsIgnoreCase(GCookie c1, GCookie c2) {
    return equalsIgnoreCase(c1.getName(), c2.getName())
        && Objects.equals(c1.getValue(), c2.getValue())
        && equalsIgnoreCase(c1.getDomain(), c2.getDomain())
        && Objects.equals(c1.getPath(), c2.getPath());
  }

  private boolean expectedHasSameName(GCookie c1, GCookie c2) {
    return equalsIgnoreCase(c1.getName(), c2.getName())
        && equalsIgnoreCase(c1.getDomain(), c2.getDomain())
        && Objects.equals(c1.getPath(), c2.getPath());
  }

  private boolean equalsIgnoreCase(String s1, String s2) {
    if (s1 == null) { return s2 == null; }
    if (s2 == null) { return false; }
    return s1.equalsIgnoreCase(s2);
  }

  private void tryStringSetter(String rootName, String[] goodValues, String[] badValues) {
    tryStringSetter(rootName, goodValues, badValues, Functions.<String>identity());
  }

  private void tryStringSetter(String rootName, String[] goodValues, String[] badValues,
      Function<String, String> mapValue) {
    trySetter(rootName, String.class, STRING_CAST, goodValues, badValues, mapValue);
    trySetterWithNull(rootName, String.class);
  }

  private static final Function<Object, String> STRING_CAST = new Function<Object, String>() {
    @Override
    public String apply(Object object) {
      return String.class.cast(object);
    }
  };

  private void tryBooleanSetter(String rootName) {
    trySetter(rootName, Boolean.TYPE, BOOLEAN_CAST, GOOD_BOOLEAN, null,
        Functions.<Boolean>identity());
  }

  private static final Function<Object, Boolean> BOOLEAN_CAST = new Function<Object, Boolean>() {
    @Override
    public Boolean apply(Object object) {
      return Boolean.class.cast(object);
    }
  };

  @SuppressWarnings("unused")
  private void tryIntegerSetter(String rootName, Integer[] goodValues, Integer[] badValues,
      Function<Integer, Integer> mapValue) {
    trySetter(rootName, Integer.TYPE, INTEGER_CAST, goodValues, badValues, mapValue);
  }

  private static final Function<Object, Integer> INTEGER_CAST = new Function<Object, Integer>() {
    @Override
    public Integer apply(Object object) {
      return Integer.class.cast(object);
    }
  };

  private void tryLongSetter(String rootName, Long[] goodValues, Long[] badValues) {
    tryLongSetter(rootName, goodValues, badValues, Functions.<Long>identity());
  }

  private void tryLongSetter(String rootName, Long[] goodValues, Long[] badValues,
      Function<Long, Long> mapValue) {
    trySetter(rootName, Long.TYPE, LONG_CAST, goodValues, badValues, mapValue);
  }

  private static final Function<Object, Long> LONG_CAST = new Function<Object, Long>() {
    @Override
    public Long apply(Object object) {
      return Long.class.cast(object);
    }
  };

  private <T> void trySetter(String rootName, Class<T> argType, Function<Object, T> valueCast,
      T[] goodValues, T[] badValues, Function<T, T> mapValue) {
    List<RunnableTest> tests = Lists.newArrayList();
    Method setter = getSetter("set" + rootName, argType);
    for (String name : GOOD_NAME) {
      for (T value : goodValues) {
        tests.add(
            CallableTest.make(setterCallable(setter, name, value),
                new GCookieExpectation<T>("get" + rootName, mapValue.apply(value), valueCast)));
      }
      if (badValues != null) {
        for (T value : badValues) {
          tests.add(CallableTest.make(setterCallable(setter, name, value), ILLEGAL_ARGUMENT));
        }
      }
    }
    runTests(tests);
  }

  private <T> void trySetterWithNull(String rootName, Class<T> argType) {
    List<RunnableTest> tests = Lists.newArrayList();
    Method setter = getSetter("set" + rootName, argType);
    for (String name : GOOD_NAME) {
      tests.add(
          CallableTest.make(
              setterCallable(setter, name, null),
              SimpleExceptionExpectation.<GCookie>make(NullPointerException.class)));
    }
    runTests(tests);
  }

  private <T> Callable<GCookie> setterCallable(final Method setter, final String name,
      final T value) {
    return new Callable<GCookie>() {
      @Override
      public GCookie call() throws Exception {
        GCookie.Builder builder = GCookie.builder(name);
        MethodTest.invokeMethod(GCookie.Builder.class, setter, builder, value);
        return builder.build();
      }
    };
  }

  private static final class GCookieExpectation<T> extends AbstractValueExpectation<GCookie> {
    final String name;
    final T expectedValue;
    final Function<Object, T> valueCast;
    final Method accessor;

    GCookieExpectation(String name, Object value, Function<Object, T> valueCast) {
      this.name = name;
      expectedValue = valueCast.apply(value);
      this.valueCast = valueCast;
      accessor = getAccessor(name);
    }

    @Override
    public String handleReturnValue(GCookie cookie) {
      if (cookie == null) {
        return "Expected non-null cookie, but got null";
      }
      try {
        T actualValue = valueCast.apply(MethodTest.invokeMethod(Object.class, accessor, cookie));
        if (!Objects.equals(expectedValue, actualValue)) {
          return "Expected " + name + "() to return " + Stringify.object(expectedValue)
              + " but instead it returned " + Stringify.object(actualValue);
        }
      } catch (Exception e) {
        fail("Getter threw exception: " + e);
      }
      return null;
    }
  }

  private static Method getAccessor(String name) {
    return MethodTest.getMethod(GCookie.class, name);
  }

  private static Method getSetter(String name, Class<?> argType) {
    return MethodTest.getMethod(GCookie.Builder.class, name, argType);
  }
}
