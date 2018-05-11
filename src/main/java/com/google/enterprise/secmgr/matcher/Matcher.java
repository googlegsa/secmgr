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

package com.google.enterprise.secmgr.matcher;

import com.google.common.base.Function;
import com.google.common.base.Functions;
import com.google.common.base.Preconditions;
import com.google.common.base.Predicate;
import com.google.common.base.Predicates;
import com.google.common.collect.ImmutableList;
import java.util.function.BiFunction;
import javax.annotation.Nonnegative;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;

/**
 * The matcher abstraction.  All other matchers extend this class.
 *
 */
@Immutable
@ParametersAreNonnullByDefault
public abstract class Matcher {

  interface BinaryPredicate<A, B> {
    boolean eval(A a, B b);
  }

  private static final BinaryPredicate<Object, Object> EQUALS =
      new BinaryPredicate<Object, Object>() {
        @Override
        public boolean eval(Object value1, Object value2) {
          return java.util.Objects.equals(value1, value2);
        }
      };

  private static final BinaryPredicate<Object, Object> STR_EQUALS_IGNORE_CASE =
      new BinaryPredicate<Object, Object>() {
        @Override
        public boolean eval(Object value1, Object value2) {
          return ((String) value1).equalsIgnoreCase((String) value2);
        }
      };

  /**
   * Each matcher must implement the following method.  The method's
   * implementation entirely defines the matcher's behavior.
   * <p>
   * This method is responsible for matching forward from a given position.  If
   * the matcher is successful, it invokes the given {@link Succeed}
   * continuation.  If the matcher fails, it invokes the given {@link Fail}
   * continuation.  The continuations are invoked tail-recursively; since Java
   * doesn't support tail recursion, the tail-recursive calls are simulated (see
   * {@link #topLevelMatch(Position)} for details).
   * <p>
   * Matchers can be composed; see the {@link #alternatives} and
   * {@link #sequence} methods.  Usually this involves invoking one of the
   * matchers and then invoking another in either the {@link Succeed} or
   * {@link Fail} continuation.
   * <p>
   * Since these matchers are chained together using continuation-passing style,
   * they shouldn't normally be expected to return.  However, by providing
   * appropriate continuations to the composite matcher, it's possible to have
   * the composite return a meaningful value.  Again, see
   * {@link #topLevelMatch(Position)} for details.
   *
   * @param state The matcher state to start matching with.
   * @param succeed A continuation to be called if the match succeeds.
   * @param fail A continuation to be called if the match fails.
   * @return The result of the matching process.
   */
  @Nonnull
  protected abstract Result match(State state, Succeed succeed, Fail fail);

  // **************** Top level ****************

  /**
   * Performs a top-level match of this matcher to a given string.  The matcher
   * does not have to match the entire string.
   *
   * @param string The string to match against.
   * @return If the match is successful, a result all of the matcher state at
   *     the end of the match.  If the match fails, {@code null} is returned.
   */
  @Nullable
  public SucceedResult topLevelMatch(String string) {
    return topLevelMatch(position(string));
  }

  /**
   * Gets a new string position.
   *
   * @param string The string that is the input sequence to use.
   * @return The initial position in that string.
   * @throws IllegalArgumentException if the string isn't well formed.
   */
  @Nonnull
  public static Position position(String string) {
    return StringPosition.make(string);
  }

  /**
   * Performs a top-level match of this matcher to a given position.  The
   * matcher does not have to match the entire input sequence.
   *
   * @param position The position to match against.
   * @return If the match is successful, a result all of the matcher state at
   *     the end of the match.  If the match fails, {@code null} is returned.
   */
  @Nullable
  public SucceedResult topLevelMatch(Position position) {
    return finishTopLevelMatch(
        match(State.make(position, ValueStack.empty(), Dict.empty()),
            TOP_LEVEL_SUCCEED, TOP_LEVEL_FAIL));
  }

  /**
   * Continues a top-level match.  Given a successful result from a top-level
   * match, fails the match to get the next possible result.
   *
   * @param previousResult A previous successful result.
   * @return If the match is successful, a result all of the matcher state at
   *     the end of the match.  If the match fails, {@code null} is returned.
   */
  @Nullable
  public static SucceedResult continueTopLevelMatch(SucceedResult previousResult) {
    return finishTopLevelMatch(previousResult.getFail().apply());
  }

  @Nullable
  private static SucceedResult finishTopLevelMatch(Result result) {
    while (result instanceof TailCallResult) {
      result = ((TailCallResult) result).call();
    }
    return (result instanceof FailResult)
        ? null
        : (SucceedResult) result;
  }

  @Nonnull private static final Succeed TOP_LEVEL_SUCCEED =
      new Succeed() {
        @Override
        protected Result applyInternal(State state, Fail fail) {
          return SucceedResult.make(state, fail);
        }
      };

  @Nonnull private static final Fail TOP_LEVEL_FAIL =
      new Fail() {
        @Override
        protected Result applyInternal() {
          return FailResult.make();
        }
      };

  // **************** Generic matchers ****************

  /**
   * Makes a new matcher that fetches a value, passes it to a predicate, and
   * succeeds or fails depending on the predicate's value.
   *
   * @param predicate The predicate to be called.
   * @param operand The value fetcher.
   * @return The corresponding matcher.
   */
  @Nonnull
  public static Matcher matcher(final Predicate<Object> predicate, final Operand operand) {
    Preconditions.checkNotNull(predicate);
    Preconditions.checkNotNull(operand);
    return new Matcher() {
      @Override
      protected Result match(State state, Succeed succeed, Fail fail) {
        OperandResult r = operand.get(state);
        return (r.getValue() != null && predicate.apply(r.getValue()))
            ? succeed.apply(r.getState(), fail)
            : fail.apply();
      }
    };
  }

  /**
   * Makes a new matcher that fetches two values, passes them to a predicate,
   * and succeeds or fails depending on the predicate's value.
   *
   * @param predicate The predicate to be called.
   * @param operand1 The fetcher for the first value.
   * @param operand2 The fetcher for the second value.
   * @return The corresponding matcher.
   */
  @Nonnull
  public static Matcher matcher(final BinaryPredicate<Object, Object> predicate,
      final Operand operand1, final Operand operand2) {
    Preconditions.checkNotNull(predicate);
    Preconditions.checkNotNull(operand1);
    Preconditions.checkNotNull(operand2);
    return new Matcher() {
      @Override
      protected Result match(State state, Succeed succeed, Fail fail) {
        OperandResult r1 = operand1.get(state);
        if (r1.getValue() == null) {
          return fail.apply();
        }
        OperandResult r2 = operand2.get(r1.getState());
        if (r2.getValue() == null) {
          return fail.apply();
        }
        return predicate.eval(r1.getValue(), r2.getValue())
            ? succeed.apply(r2.getState(), fail)
            : fail.apply();
      }
    };
  }

  /**
   * Makes a new matcher that fetches two values, passes them to a predicate,
   * and succeeds or fails depending on the predicate's value.  Unlike a normal
   * matcher, the fetch of the second value depends on the first value.
   *
   * @param predicate The predicate to be called.
   * @param operand1 The fetcher for the first value.
   * @param getValue2 A function to get the second value.
   * @return The corresponding matcher.
   */
  @Nonnull
  public static Matcher matcher(final BinaryPredicate<Object, Object> predicate,
      final Operand operand1, final Function<OperandResult, OperandResult> getValue2) {
    Preconditions.checkNotNull(predicate);
    Preconditions.checkNotNull(operand1);
    Preconditions.checkNotNull(getValue2);
    return new Matcher() {
      @Override
      protected Result match(State state, Succeed succeed, Fail fail) {
        OperandResult r1 = operand1.get(state);
        if (r1.getValue() == null) {
          return fail.apply();
        }
        OperandResult r2 = getValue2.apply(r1);
        if (r2.getValue() == null) {
          return fail.apply();
        }
        return predicate.eval(r1.getValue(), r2.getValue())
            ? succeed.apply(r2.getState(), fail)
            : fail.apply();
      }
    };
  }

  /**
   * Makes a new operator that fetches a value, passes it to a function, and
   * stores the function's result.
   *
   * @param function The function to be called.
   * @param operand The value fetcher.
   * @param store The result storer.
   * @return The corresponding operator.
   */
  @Nonnull
  public static Matcher operator(final Function<Object, Object> function,
      final Operand operand, final Store store) {
    Preconditions.checkNotNull(function);
    Preconditions.checkNotNull(operand);
    Preconditions.checkNotNull(store);
    return new Matcher() {
      @Override
      protected Result match(State state, final Succeed succeed, Fail fail) {
        OperandResult r1 = operand.get(state);
        if (r1.getValue() == null) {
          return fail.apply();
        }
        Object value = function.apply(r1.getValue());
        if (value == null) {
          return fail.apply();
        }
        return succeed.apply(store.put(value, r1.getState()), fail);
      }
    };
  }

  /**
   * Makes a new operator that fetches two values, passes them to a function,
   * and stores the function's result.
   *
   * @param function The function to be called.
   * @param operand1 The fetcher for the first value.
   * @param operand2 The fetcher for the second value.
   * @param store The result storer.
   * @return The corresponding operator.
   */
  @Nonnull
  public static Matcher operator(final BiFunction<Object, Object, Object> function,
      final Operand operand1, final Operand operand2, final Store store) {
    Preconditions.checkNotNull(function);
    Preconditions.checkNotNull(operand1);
    Preconditions.checkNotNull(operand2);
    Preconditions.checkNotNull(store);
    return new Matcher() {
      @Override
      protected Result match(State state, Succeed succeed, Fail fail) {
        OperandResult r1 = operand1.get(state);
        if (r1.getValue() == null) {
          return fail.apply();
        }
        OperandResult r2 = operand2.get(r1.getState());
        if (r2.getValue() == null) {
          return fail.apply();
        }
        Object value = function.apply(r1.getValue(), r2.getValue());
        if (value == null) {
          return fail.apply();
        }
        return succeed.apply(store.put(value, r2.getState()), fail);
      }
    };
  }

  /**
   * Gets a matcher that's the same as this matcher except that it fetches a
   * value before the match, fetches another value after a successful match,
   * passes the two values to a given function, and stores the function's
   * result.
   *
   * @param function The function to be called.
   * @param operand1 The fetcher for the first value (pre match).
   * @param operand2 The fetcher for the second value (post match).
   * @param store The result storer.
   * @return The corresponding operator.
   */
  @Nonnull
  public Matcher wrapper(final BiFunction<Object, Object, Object> function,
      final Operand operand1, final Operand operand2, final Store store) {
    Preconditions.checkNotNull(function);
    Preconditions.checkNotNull(operand1);
    Preconditions.checkNotNull(operand2);
    Preconditions.checkNotNull(store);
    final Matcher matcher = this;
    return new Matcher() {
      @Override
      protected Result match(State state, final Succeed succeed, Fail fail) {
        final OperandResult r1 = operand1.get(state);
        return matcher.match(r1.getState(),
            new Succeed() {
              @Override
              protected Result applyInternal(State state2, Fail fail2) {
                OperandResult r2 = operand2.get(state2);
                Object value = function.apply(r1.getValue(), r2.getValue());
                return (value != null)
                    ? succeed.apply(store.put(value, r2.getState()), fail2)
                    : fail2.apply();
              }
            },
            fail);
      }
    };
  }

  // **************** Repetition ****************

  /**
   * Returns a new matcher that greedily matches the current matcher multiple
   * times.  The resulting matcher succeeds if it is able to match the specified
   * number of times.
   *
   * @param min The minimum number of times the current matcher will be matched.
   * @param max The maximum number of times the current matcher will be matched.
   * @return The new repeating matcher.
   * @throws IllegalArgumentException if {@code min} is negative or {@code max}
   *     is less than {@code min}.
   */
  @Nonnull
  public Matcher repeat(@Nonnegative int min, @Nonnegative int max) {
    return GreedyRepeater.make(this, min, max);
  }

  /**
   * Returns a new matcher that lazily matches the current matcher multiple
   * times.  The resulting matcher succeeds if it is able to match the specified
   * number of times.
   *
   * @param min The minimum number of times the current matcher will be matched.
   * @param max The maximum number of times the current matcher will be matched.
   * @return The new repeating matcher.
   * @throws IllegalArgumentException if {@code min} is negative or {@code max}
   *     is less than {@code min}.
   */
  @Nonnull
  public Matcher lazyRepeat(@Nonnegative int min, @Nonnegative int max) {
    return LazyRepeater.make(this, min, max);
  }

  /**
   * A convenience method for {@code greedyRepeat(n, n)}.
   *
   * @param n The number of times the matcher will be matched.
   * @return The new repeating matcher.
   * @throws IllegalArgumentException if {@code n} is negative.
   */
  @Nonnull
  public Matcher repeat(@Nonnegative int n) {
    return repeat(n, n);
  }

  /**
   * A convenience method for {@code lazyRepeat(n, n)}.
   *
   * @param n The number of times the matcher will be matched.
   * @return The new repeating matcher.
   * @throws IllegalArgumentException if {@code n} is negative.
   */
  @Nonnull
  public Matcher lazyRepeat(@Nonnegative int n) {
    return lazyRepeat(n, n);
  }

  /**
   * A convenience method for {@code repeat(0, Integer.MAX_VALUE)}.
   *
   * @return The new repeating matcher.
   */
  @Nonnull
  public Matcher star() {
    return repeat(0, Integer.MAX_VALUE);
  }

  /**
   * A convenience method for {@code lazyRepeat(0, Integer.MAX_VALUE)}.
   *
   * @return The new repeating matcher.
   */
  @Nonnull
  public Matcher lazyStar() {
    return lazyRepeat(0, Integer.MAX_VALUE);
  }

  /**
   * A convenience method for {@code repeat(1, Integer.MAX_VALUE)}.
   *
   * @return The new repeating matcher.
   */
  @Nonnull
  public Matcher plus() {
    return repeat(1, Integer.MAX_VALUE);
  }

  /**
   * A convenience method for {@code lazyRepeat(1, Integer.MAX_VALUE)}.
   *
   * @return The new repeating matcher.
   */
  @Nonnull
  public Matcher lazyPlus() {
    return lazyRepeat(1, Integer.MAX_VALUE);
  }

  /**
   * A convenience method for {@code repeat(0, 1)}.
   *
   * @return The new optional matcher.
   */
  @Nonnull
  public Matcher optional() {
    return repeat(0, 1);
  }

  /**
   * A convenience method for {@code lazyRepeat(0, 1)}.
   *
   * @return The new optional matcher.
   */
  @Nonnull
  public Matcher lazyOptional() {
    return lazyRepeat(0, 1);
  }

  // **************** Value management ****************

  /**
   * Gets a matcher that's the same as this matcher except that it pushes the
   * matched string onto the value stack.
   */
  @Nonnull
  public Matcher pushMatchedString() {
    return wrapper(GET_STRING_FUNCTION,
        Operands.position(),
        Operands.position(),
        Stores.push());
  }

  /**
   * Gets an operator that pushes a given value onto the value stack.
   */
  @Nonnull
  public static Matcher pushValue(Object value) {
    return operator(Functions.identity(), Operands.constant(value), Stores.push());
  }

  /**
   * Gets a matcher that's the same as this matcher except that it saves the
   * matched string into the dictionary with a given key.
   *
   * @param key The key to store the value with.
   * @return The corresponding matcher.
   */
  @Nonnull
  public Matcher putMatchedString(Object key) {
    return wrapper(GET_STRING_FUNCTION,
        Operands.position(),
        Operands.position(),
        Stores.put(key));
  }

  @Nonnull private static final BiFunction<Object, Object, Object> GET_STRING_FUNCTION =
      new BiFunction<Object, Object, Object>(){
        @Override
        public Object apply(Object object1, Object object2) {
          Position startPosition = (Position) object1;
          Position endPosition = (Position) object2;
          return endPosition.getString(startPosition);
        }
      };

  /**
   * Gets a matcher that's the same as this matcher except that, after matching,
   * it pops all values pushed onto the value stack by this matcher, makes a
   * list of them in parse order, and pushes that on the value stack.
   */
  @Nonnull
  public Matcher collectValues() {
    return wrapper(COLLECT_VALUES_FUNCTION,
        Operands.newStack(),
        Operands.stack(),
        Stores.stack());
  }

  @Nonnull private static final BiFunction<Object, Object, Object> COLLECT_VALUES_FUNCTION =
      new BiFunction<Object, Object, Object>() {
        @Override
        public Object apply(Object object1, Object object2) {
          ValueStack originalStack = (ValueStack) object1;
          ValueStack newStack = (ValueStack) object2;
          return originalStack.push(newStack.toList());
        }
      };

  /**
   * Gets a matcher that pops a value off of the value stack and passes the
   * value to a predicate.  If the predicate returns true, the match succeeds,
   * otherwise it fails.
   * <p>
   * The resulting operator will throw an exception if there are no values on
   * the stack when it tries to pop one.
   *
   * @param predicate The predicate to be called.
   * @return The corresponding matcher.
   */
  @Nonnull
  public static Matcher matchPoppedValue(Predicate<Object> predicate) {
    return matcher(predicate, Operands.pop());
  }

  /**
   * Gets an operator that transforms the top of the value stack with a given
   * function.  The value at the top of the stack is popped and passed to the
   * function, and the resulting value is pushed on the stack.
   * <p>
   * The resulting operator will throw an exception if there are no values on
   * the stack when it tries to pop one.
   *
   * @param function The transformation function.
   * @return The corresponding operator.
   */
  @Nonnull
  public static Matcher transformTopValue(Function<Object, Object> function) {
    return operator(function, Operands.pop(), Stores.push());
  }

  /**
   * Gets an operator that pops the top of the value stack and saves it in the
   * dictionary with the given key.
   * <p>
   * The resulting matcher will throw an exception if there are no values on the
   * stack when it tries to pop one.
   *
   * @param key The key to bind the value to.
   * @return The corresponding matcher.
   */
  @Nonnull
  public static Matcher popValueAndPut(Object key) {
    return operator(Functions.identity(), Operands.pop(), Stores.put(key));
  }

  /**
   * Gets a matcher that looks up a value in the dictionary and pushes it onto
   * the value stack.
   * <p>
   * The resulting matcher will throw an exception if the dictionary doesn't
   * have a value for the given key.
   *
   * @param key The key to look up in the dictionary.
   * @return The corresponding matcher.
   */
  @Nonnull
  public static Matcher getValueAndPush(Object key) {
    return operator(Functions.identity(), Operands.get(key), Stores.push());
  }

  // **************** Position matchers ****************

  /**
   * Gets a matcher that matches any position satisfying a given predicate.
   *
   * @param predicate The predicate to be called.
   * @return The corresponding character matcher.
   */
  @Nonnull
  public static Matcher positionMatcher(final Predicate<Position> predicate) {
    Preconditions.checkNotNull(predicate);
    return matcher(
        new Predicate<Object>() {
          @Override
          public boolean apply(Object object) {
            return predicate.apply((Position) object);
          }
        },
        Operands.position());
  }

  /**
   * Gets a matcher that succeeds only when it's at the start of the input
   * sequence.
   */
  @Nonnull
  public static Matcher atStart() {
    return AT_START_MATCHER;
  }

  /**
   * Gets a matcher that succeeds only when it's at the end of the input
   * sequence.
   */
  @Nonnull
  public static Matcher atEnd() {
    return AT_END_MATCHER;
  }

  /**
   * Gets a matcher that succeeds only when it's at the start of a line.
   */
  @Nonnull
  public static Matcher atLineStart() {
    return AT_LINE_START_MATCHER;
  }

  /**
   * Gets a matcher that succeeds only when it's at the end of a line.
   */
  @Nonnull
  public static Matcher atLineEnd() {
    return AT_LINE_END_MATCHER;
  }

  @Nonnull private static final Matcher AT_START_MATCHER =
      positionMatcher(
          new Predicate<Position>() {
            @Override
            public boolean apply(Position position) {
              return !position.hasPrevChar();
            }
          });

  @Nonnull private static final Matcher AT_END_MATCHER =
      positionMatcher(
          new Predicate<Position>() {
            @Override
            public boolean apply(Position position) {
              return !position.hasChar();
            }
          });

  @Nonnull private static final Matcher AT_LINE_START_MATCHER =
      positionMatcher(
          new Predicate<Position>() {
            @Override
            public boolean apply(Position position) {
              return atLineStart(position);
            }
          });

  private static boolean atLineStart(Position position) {
    if (!position.hasPrevChar()) {
      return true;
    }
    int cp = position.getPrevChar();
    return Unicode.isLineBreak(cp)
        && !(cp == Unicode.CARRIAGE_RETURN
             && position.hasChar()
             && position.getChar() == Unicode.LINE_FEED);
  }

  @Nonnull private static final Matcher AT_LINE_END_MATCHER =
      positionMatcher(
          new Predicate<Position>() {
            @Override
            public boolean apply(Position position) {
              return atLineEnd(position);
            }
          });

  private static boolean atLineEnd(Position position) {
    if (!position.hasChar()) {
      return true;
    }
    int cp = position.getChar();
    return Unicode.isLineBreak(cp)
        && !(cp == Unicode.LINE_FEED
             && position.hasPrevChar()
             && position.getPrevChar() == Unicode.CARRIAGE_RETURN);
  }

  // **************** Character matchers ****************

  /**
   * Gets a matcher that matches any character satisfying a given predicate.
   *
   * @param predicate The predicate to be called.
   * @return The corresponding character matcher.
   */
  @Nonnull
  public static Matcher charMatcher(final Predicate<Integer> predicate) {
    Preconditions.checkNotNull(predicate);
    return matcher(
        new Predicate<Object>() {
          @Override
          public boolean apply(Object object) {
            return predicate.apply((Integer) object);
          }
        },
        Operands.nextChar());
  }

  /**
   * Gets a matcher that exactly matches a given character.
   *
   * @param c The character to match.
   * @return The corresponding character matcher.
   */
  @Nonnull
  public static Matcher literal(final int c) {
    Preconditions.checkArgument(Unicode.isCharacter(c));
    return charMatcher(
        new Predicate<Integer>() {
          @Override
          public boolean apply(Integer c2) {
            return c2.intValue() == c;
          }
        });
  }

  /**
   * Gets a matcher that matches any character.
   */
  @Nonnull
  public static Matcher anyChar() {
    return ANY_CHAR;
  }

  /**
   * Gets a matcher that matches any whitespace character.
   */
  @Nonnull
  public static Matcher whitespace() {
    return WHITESPACE_CHAR;
  }

  /**
   * Gets a matcher that matches any digit.
   */
  @Nonnull
  public static Matcher digit() {
    return DIGIT_CHAR;
  }

  /**
   * Gets a matcher that matches any character in a given set.
   *
   * @param set The character set to be matched.
   * @return The corresponding character matcher.
   */
  @Nonnull
  public static Matcher oneOf(CharSet set) {
    return charMatcher(set.isMemberPredicate());
  }

  /**
   * Gets a matcher that matches any character in a given string.
   *
   * @param string The string containing the characters to be matched.
   * @return The corresponding character matcher.
   */
  @Nonnull
  public static Matcher oneOf(String string) {
    return oneOf(CharSet.make(string));
  }

  @Nonnull private static final Matcher ANY_CHAR = charMatcher(Predicates.<Integer>alwaysTrue());
  @Nonnull private static final Matcher WHITESPACE_CHAR = charMatcher(Unicode.WHITESPACE_PREDICATE);
  @Nonnull private static final Matcher DIGIT_CHAR = charMatcher(Unicode.DIGIT_PREDICATE);

  // **************** String matchers ****************

  /**
   * Gets a matcher that fetches a string value using a given operand, and
   * matches that value against the input sequence using a given predicate.
   *
   * @param predicate The predicate to match the two strings.
   * @param operand The fetcher for the first string value.
   * @return The corresponding string matcher.
   */
  @Nonnull
  public static Matcher stringMatcher(BinaryPredicate<Object, Object> predicate,
      Operand operand) {
    return matcher(predicate,
        operand,
        new Function<OperandResult, OperandResult>() {
          @Override
          public OperandResult apply(OperandResult result) {
            int nChars = Unicode.length((String) result.getValue());
            return Operands.nextChars(nChars).get(result.getState());
          }
        });
  }

  /**
   * Gets a matcher that exactly matches a given string.
   *
   * @param literal The string to be matched.
   * @return The corresponding string matcher.
   */
  @Nonnull
  public static Matcher literal(String literal) {
    Preconditions.checkArgument(Unicode.isWellFormed(literal));
    return stringMatcher(EQUALS, Operands.constant(literal));
  }

  /**
   * Gets a matcher that exactly matches a string from the dictionary.
   *
   * @param key The key to use when fetching from the dictionary.
   * @return The corresponding string matcher.
   */
  @Nonnull
  public static Matcher getMatcher(Object key) {
    return stringMatcher(EQUALS, Operands.get(key));
  }

  /**
   * Gets a matcher that exactly matches a given string, ignoring case.
   *
   * @param literal The string to be matched.
   * @return The corresponding string matcher.
   */
  @Nonnull
  public static Matcher literalIgnoreCase(String literal) {
    Preconditions.checkArgument(Unicode.isWellFormed(literal));
    return stringMatcher(STR_EQUALS_IGNORE_CASE, Operands.constant(literal));
  }

  // **************** Matcher combinators ****************

  /**
   * Gets a composite matcher that matches the given component matchers in
   * order.  If one of the component matchers succeeds, the composite matcher
   * succeeds.  If one of the component matchers fails, the next component in
   * the list is tried starting at the same position.
   *
   * @param matchers The component matchers to try.
   * @return A composite matcher.
   */
  @Nonnull
  public static Matcher alternatives(Matcher... matchers) {
    switch (matchers.length) {
      case 0:
        return ALWAYS_FAIL;
      case 1:
        return matchers[0];
      default:
        return Alternatives.make(ImmutableList.copyOf(matchers));
    }
  }

  @Nonnull private static final Matcher ALWAYS_FAIL =
      new Matcher() {
        @Override
        protected Result match(State state, Succeed succeed, Fail fail) {
          return fail.apply();
        }
      };

  /**
   * Gets a composite matcher that matches the given component matchers in
   * order.  If one of the component matchers fails, the composite match fails.
   * Otherwise, the composite match is the concatenation of the component
   * matches.
   *
   * @param matchers The component matchers to try.
   * @return A composite matcher.
   */
  @Nonnull
  public static Matcher sequence(Matcher... matchers) {
    switch (matchers.length) {
      case 0:
        return ALWAYS_SUCCEED;
      case 1:
        return matchers[0];
      default:
        return Sequence.make(ImmutableList.copyOf(matchers));
    }
  }

  @Nonnull private static final Matcher ALWAYS_SUCCEED =
      new Matcher() {
        @Override
        protected Result match(State state, Succeed succeed, Fail fail) {
          return succeed.apply(state, fail);
        }
      };
}
