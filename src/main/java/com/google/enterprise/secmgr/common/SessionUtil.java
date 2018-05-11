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

package com.google.enterprise.secmgr.common;

import com.google.common.base.Strings;
import com.google.enterprise.sessionmanager.SessionManagerInterfaceBase;
import java.util.List;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.servlet.http.HttpServletRequest;

/**
 * A collection of session utilities.
 */
@ParametersAreNonnullByDefault
@ThreadSafe
public final class SessionUtil {

  /**
   * The name of the GSA session ID cookie.
   */
  public static final String GSA_SESSION_ID_COOKIE_NAME = "GSA_SESSION_ID";

  public static final String GSA_REQUEST_ID_PARAM_NAME = "gsaRequestId";
  public static final String GSA_REQUEST_ID_HEADER_NAME = "Gsa-Request-Id";

  @GuardedBy("SessionUtil.class")
  private static SessionManagerInterfaceBase gsaSessionManager = null;

  /**
   * A regular expression that matches a valid session ID; basically alphanumeric.
   */
  // TODO: might be useful to broaden this pattern to handle base64.
  private static final Pattern SESSION_ID_REGEXP = Pattern.compile("[0-9A-Za-z]*");

  /**
   * The smallest acceptable length for a session ID string.
   */
  private static final int MIN_ACCEPTABLE_SESSION_ID_LENGTH = 16;

  /**
   * The largest acceptable length for a session ID string.
   */
  private static final int MAX_ACCEPTABLE_SESSION_ID_LENGTH = 100;

  /**
   * The length of a generated session ID string.
   */
  private static final int GENERATED_SESSION_ID_LENGTH = MIN_ACCEPTABLE_SESSION_ID_LENGTH;

  // Don't instantiate.
  private SessionUtil() {
    throw new UnsupportedOperationException();
  }

  /**
   * Generates a session ID for a new session.
   */
  @Nonnull
  public static String generateId() {
    return SecurityManagerUtil.generateRandomNonceHex(GENERATED_SESSION_ID_LENGTH / 2);
  }

  /**
   * Is the given string a valid session ID?
   *
   * @param proposedId The string to test.
   * @return True only if the string is valid.
   */
  public static boolean isValidId(@Nullable String proposedId) {
    return proposedId != null
        && proposedId.length() >= MIN_ACCEPTABLE_SESSION_ID_LENGTH
        && proposedId.length() <= MAX_ACCEPTABLE_SESSION_ID_LENGTH
        && SESSION_ID_REGEXP.matcher(proposedId).matches();
  }

  /**
   * Gets the GSA session ID by examining the cookies in an incoming request.
   *
   * @param request The HTTP request to check the cookies of.
   * @return The GSA session ID, if a valid one is found; otherwise null.
   */
  @Nullable
  public static String findGsaSessionId(HttpServletRequest request) {
    CookieStore cookies = GCookie.parseHttpRequestCookies(request);
    for (GCookie c : cookies) {
      if (GSA_SESSION_ID_COOKIE_NAME.equalsIgnoreCase(c.getName())
          && isValidId(c.getValue())) {
        return c.getValue();
      }
    }
    return null;
  }

  @Nullable
  public static String findGsaRequestId(HttpServletRequest request) {
    List<String> paramVals = HttpUtil
        .decodeQueryString(request.getQueryString())
        .get(GSA_REQUEST_ID_PARAM_NAME);
    if (paramVals == null || paramVals.isEmpty()) {
      return request.getHeader(GSA_REQUEST_ID_HEADER_NAME);
    }
    return paramVals.get(0);
  }

  /**
   * Decorates a log message with a given session ID.
   *
   * @param sessionId The session ID to decorate the message with.
   * @param message The log message to decorate.
   * @return The decorated log message.
   */
  @Nonnull
  public static String logMessage(@Nullable String sessionId, String message) {
    return Strings.isNullOrEmpty(sessionId)
        ? message
        : "sid " + sessionId + ": " + message;
  }

  /**
   * Gets a log-message decorator for a given session ID.
   *
   * @param sessionId The session ID to use.
   * @return A log-message decorator for that ID.
   */
  @Nonnull
  public static Decorator getLogDecorator(@Nullable final String sessionId) {
    return Strings.isNullOrEmpty(sessionId)
        ? getLogDecorator()
        : new Decorator() {
            @Override
            public String apply(String message) {
              return decorate(sessionId, message);
            }
          };
  }

  private static String decorate(String sessionId, String message) {
    return "sid " + sessionId + ": " + message;
  }

  /**
   * Gets a log-message decorator for a given HTTP request.  Tries to get the
   * session ID from the request and uses that.
   *
   * @param request The HTTP request to use.
   * @return A log-message decorator for that request.
   */
  @Nonnull
  public static Decorator getLogDecorator(HttpServletRequest request) {
    return getLogDecorator(findGsaSessionId(request));
  }

  /**
   * Gets a null log-message decorator.  This decorator is an identity function.
   *
   * @return A null log-message decorator.
   */
  @Nonnull
  public static Decorator getLogDecorator() {
    return new Decorator() {
      @Override
      public String apply(String message) {
        return message;
      }
    };
  }

  // Gets a reference to the GSA's session manager.
  public static synchronized SessionManagerInterfaceBase getGsaSessionManager() {
    if (gsaSessionManager == null) {
      // Default Session Manager (flag values should be available at this
      // stage - they would not be inside a static clause).
      gsaSessionManager = SessionManagerFactory.create();
    }
    return gsaSessionManager;
  }

  public static synchronized void setGsaSessionManager(SessionManagerInterfaceBase sessionManager) {
    gsaSessionManager = sessionManager;
  }
}
