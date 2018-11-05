// Copyright 2009 Google Inc.
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

import static java.nio.charset.StandardCharsets.ISO_8859_1;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.CharMatcher;
import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.Multimap;
import com.google.common.io.CharStreams;
import com.google.enterprise.secmgr.matcher.CharSet;
import com.google.enterprise.secmgr.matcher.Matcher;
import com.google.enterprise.secmgr.matcher.SucceedResult;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.UnsupportedCharsetException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Static methods for fetching pages via HTTP.  See RFCs 2616 and 2617 for
 * details.
 */
public final class HttpUtil {

  public static final String HTTP_METHOD_GET = "GET";
  public static final String HTTP_METHOD_POST = "POST";
  public static final String HTTP_METHOD_HEAD = "HEAD";

  // HTTP header names.
  public static final String HTTP_HEADER_ACCEPT = "Accept";
  public static final String HTTP_HEADER_ACCEPT_CHARSET = "Accept-Charset";
  public static final String HTTP_HEADER_ACCEPT_ENCODING = "Accept-Encoding";
  public static final String HTTP_HEADER_ACCEPT_LANGUAGE = "Accept-Language";
  public static final String HTTP_HEADER_AUTHORIZATION = "Authorization";
  public static final String HTTP_HEADER_CONNECTION = "Connection";
  public static final String HTTP_HEADER_CONTENT_LENGTH = "Content-Length";
  public static final String HTTP_HEADER_CONTENT_TYPE = "Content-Type";
  public static final String HTTP_HEADER_COOKIE = "Cookie";
  public static final String HTTP_HEADER_DATE = "Date";
  public static final String HTTP_HEADER_LOCATION = "Location";
  public static final String HTTP_HEADER_PROXY_AUTHENTICATE = "Proxy-Authenticate";
  public static final String HTTP_HEADER_PROXY_AUTHORIZATION = "Proxy-Authorization";
  public static final String HTTP_HEADER_RANGE = "Range";
  public static final String HTTP_HEADER_REFERRER = "Referer";
  public static final String HTTP_HEADER_SET_COOKIE = "Set-Cookie";
  public static final String HTTP_HEADER_SET_COOKIE2 = "Set-Cookie2";
  public static final String HTTP_HEADER_USER_AGENT = "User-Agent";
  public static final String HTTP_HEADER_WWW_AUTHENTICATE = "WWW-Authenticate";

  // TODO: The rest of this file is general purpose http, but
  // this cookie-cracking code is quite security manager specific.  At some
  // point, it would be good to refactor (perhaps providing a caller
  // specified callback for custom header processing?)
  //
  // TODO: make this extensible/configurable (at least from spring).
  // These are Google-specific headers set in a response, which can set the
  // username and groups list for a credentials group.
  public static final String COOKIE_CRACK_USERNAME_HEADER = "X-Username";
  public static final String COOKIE_CRACK_GROUPS_HEADER = "X-Groups";

  // Boilerplate HTTP header values.
  public static final String KEEP_ALIVE = "keep-alive";
  // TODO: make this configurable through spring.
  public static final String USER_AGENT = "SecMgr";
  public static final String ACCEPT =
      "text/html, text/xhtml;q=0.9, text/plain;q=0.5, text/*;q=0.1";
  public static final String ACCEPT_FOR_HEAD = "*/*";
  public static final String ACCEPT_CHARSET = "us-ascii, iso-8859-1, utf-8";
  public static final String ACCEPT_ENCODING = "identity";
  public static final String ACCEPT_LANGUAGE = "en-us, en;q=0.9";
  private static final String RANGE_FORMAT = "bytes=0-%d";
  public static final String DEFAULT_MIME_TYPE = "application/octet-stream";
  public static final Charset DEFAULT_CHARSET = ISO_8859_1;
  public static final String PARAM_NAME_CHARSET = "charset";

  public static final char PARAM_VALUE_SEPARATOR = '=';
  public static final char STRING_DELIMITER = '"';
  public static final char STRING_QUOTE = '\\';
  public static final char PARAM_SEPARATOR_CHAR = ';';
  public static final String PARAM_SEPARATOR = "; ";

  public static final String TYPE_OCTET_STREAM = "application/octet-stream";

  private static final Splitter PARAM_SPLITTER = Splitter.on(PARAM_SEPARATOR_CHAR).trimResults();
  @VisibleForTesting
  static final Matcher POST_FORM_MATCHER = buildPostFormMatcher();

  // Don't instantiate.
  private HttpUtil() {
    throw new UnsupportedOperationException();
  }

  public static boolean isHttpGetMethod(String method) {
    return HTTP_METHOD_GET.equalsIgnoreCase(method);
  }

  public static boolean isHttpPostMethod(String method) {
    return HTTP_METHOD_POST.equalsIgnoreCase(method);
  }

  public static boolean isHttpHeadMethod(String method) {
    return HTTP_METHOD_HEAD.equalsIgnoreCase(method);
  }

  public static List<StringPair> getBoilerplateHeaders() {
    return getBoilerplateHeaders(false);
  }

  public static List<StringPair> getBoilerplateHeaders(boolean isHeadRequest) {
    String accept = isHeadRequest ? ACCEPT_FOR_HEAD : ACCEPT;
    return ImmutableList.of(
        new StringPair(HTTP_HEADER_ACCEPT, accept),
        new StringPair(HTTP_HEADER_ACCEPT_CHARSET, ACCEPT_CHARSET),
        new StringPair(HTTP_HEADER_ACCEPT_ENCODING, ACCEPT_ENCODING),
        new StringPair(HTTP_HEADER_ACCEPT_LANGUAGE, ACCEPT_LANGUAGE),
        new StringPair(HTTP_HEADER_DATE, ServletBase.httpDateString()));
  }

  /**
   * Does the given HTTP status code indicate a valid response?
   *
   * @param status The status code to test.
   * @return True only if it indicates a valid response.
   */
  public static boolean isGoodHttpStatus(int status) {
    return status == HttpServletResponse.SC_OK
        || status == HttpServletResponse.SC_PARTIAL_CONTENT;
  }

  public static URL urlFromString(String urlString) {
    try {
      return new URL(urlString);
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static URL urlFromString(URL baseUrl, String urlString) {
    try {
      return new URL(baseUrl, urlString);
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static URL urlFromParts(String protocol, String host, int port, String file) {
    try {
      return new URL(protocol, host, port, file);
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static URL parseUrlString(String urlString) {
    try {
      return new URL(urlString);
    } catch (MalformedURLException e) {
      return null;
    }
  }

  public static URL parseUrlString(URL baseUrl, String urlString) {
    try {
      return new URL(baseUrl, urlString);
    } catch (MalformedURLException e) {
      return null;
    }
  }

  public static URL parentUrl(URL url) {
    String path = url.getPath();
    int slash = path.lastIndexOf('/');
    if (slash <= 0) {
      return null;
    }
    return urlFromParts(url.getProtocol(), url.getHost(), url.getPort(), path.substring(0, slash));
  }

  public static URL stripQueryFromUrl(URL url) {
    return mergeQueryIntoUrl(url, null);
  }

  public static URL mergeQueryIntoUrl(URL url, String query) {
    return urlFromParts(url.getProtocol(), url.getHost(), url.getPort(),
        newQuery(url.getPath(), query));
  }

  private static String newQuery(String path, String query) {
    return Strings.isNullOrEmpty(query) ? path : path + "?" + query;
  }

  /**
   * Converts a {@link URL} to a {@link URI}.
   *
   * @param url The URL to convert.
   * @return The corresponding URI.
   * @throws IllegalArgumentException if there are any parse errors in the
   *     conversion.
   */
  public static URI toUri(URL url) {
    if (url.getHost() != null && url.getHost().contains("_")) {
      // Underscore is not a valid character in a hostname according
      // to RFC 2396, RFC 952, and RFC 1123. But names of hosts that
      // are used have underscores often enough to warrant leniancy.
      return makeUriWithUnderscoreInHostname(url);
    } 
    String proto = url.getProtocol();
    String auth = url.getAuthority();
    // be permissive with path and query b/15124880
    String file = url.getFile().replace("[", "%5B").replace("]", "%5D");
    String fragment = url.getRef();
    if (null == fragment) {
      fragment = "";
    } else {
      fragment = "#" + fragment;
    }
    return URI.create(proto + "://" + auth + file + fragment);
  }

  @VisibleForTesting
  static URI makeUriWithUnderscoreInHostname(URL url) {
    String proto = url.getProtocol();

    String userInfo = url.getUserInfo();
    String host = url.getHost();
    int port = url.getPort();

    String path = url.getPath();
    String query = url.getQuery();

    // be permissive with path and query b/15124880
    if (null != path) {
      path = path.replace("[", "%5B").replace("]", "%5D");
    }
    if (null != query) {
      query = query.replace("[", "%5B").replace("]", "%5D");
    }

    String fragment = url.getRef();

    StringBuilder authorityAssembly = new StringBuilder();
    if (null != userInfo) {
      authorityAssembly.append(userInfo).append("@");
    }
    authorityAssembly.append(host);
    if (-1 != port) {
      authorityAssembly.append(":").append(port);
    }
    String auth = authorityAssembly.toString();

    URI hacked = URI.create("");

    // work around restriction on underscores in URIs; FR: b/15127606
    try {
      java.lang.reflect.Field schemeField = URI.class.getDeclaredField("scheme");
      schemeField.setAccessible(true);
      schemeField.set(hacked, proto);
    } catch (NoSuchFieldException|IllegalAccessException ex) {
      throw new AssertionError("cannot make URI because of scheme: " + url);
    }
    try {
      java.lang.reflect.Field userInfoField = URI.class.getDeclaredField("userInfo");
      userInfoField.setAccessible(true);
      userInfoField.set(hacked, userInfo);
    } catch (NoSuchFieldException|IllegalAccessException ex) {
      throw new AssertionError("cannot make URI because of userInfo: " + url);
    }
    try {
      java.lang.reflect.Field hostField = URI.class.getDeclaredField("host");
      hostField.setAccessible(true);
      hostField.set(hacked, host);
    } catch (NoSuchFieldException|IllegalAccessException ex) {
      throw new AssertionError("cannot make URI because of host: " + url);
    }
    try {
      java.lang.reflect.Field portField = URI.class.getDeclaredField("port");
      portField.setAccessible(true);
      portField.set(hacked, port);
    } catch (NoSuchFieldException|IllegalAccessException ex) {
      throw new AssertionError("cannot make URI because of port: " + url);
    }
    try {
      java.lang.reflect.Field pathField = URI.class.getDeclaredField("path");
      pathField.setAccessible(true);
      pathField.set(hacked, path);
    } catch (NoSuchFieldException|IllegalAccessException ex) {
      throw new AssertionError("cannot make URI because of path: " + url);
    }
    try {
      java.lang.reflect.Field queryField = URI.class.getDeclaredField("query");
      queryField.setAccessible(true);
      queryField.set(hacked, query);
    } catch (NoSuchFieldException|IllegalAccessException ex) {
      throw new AssertionError("cannot make URI because of query: " + url);
    }
    try {
      java.lang.reflect.Field fragmentField = URI.class.getDeclaredField("fragment");
      fragmentField.setAccessible(true);
      fragmentField.set(hacked, fragment);
    } catch (NoSuchFieldException|IllegalAccessException ex) {
      throw new AssertionError("cannot make URI because of fragment: " + url);
    }
    try {
      java.lang.reflect.Field authField = URI.class.getDeclaredField("authority");
      authField.setAccessible(true);
      authField.set(hacked, auth);
    } catch (NoSuchFieldException|IllegalAccessException ex) {
      throw new AssertionError("cannot make URI because of authority: " + url);
    } 
    try {
      String file = path;
      if (null != query) {
        file += "?" + query;
      }
      if (null == fragment) {
        fragment = "";
      } else {
        fragment = "#" + fragment;
      }
      java.lang.reflect.Field stringField = URI.class.getDeclaredField("string");
      stringField.setAccessible(true);
      stringField.set(hacked, proto + "://" + auth + file + fragment);
      java.lang.reflect.Field schemeSpecField
          = URI.class.getDeclaredField("schemeSpecificPart");
      schemeSpecField.setAccessible(true);
      schemeSpecField.set(hacked, "//" + auth + file);
    } catch (NoSuchFieldException|IllegalAccessException ex) {
      throw new AssertionError("cannot make URI because of string: " + url);
    }

    return hacked; 
  }

  /**
   * Converts a {@link URI} to a {@link URL}.
   *
   * @param uri The URI to convert.
   * @return The corresponding URL.
   * @throws IllegalArgumentException if there are any parse errors in the
   *     conversion.
   */
  public static URL toUrl(URI uri) {
    try {
      return uri.toURL();
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Takes a given URI and returns a new one in which the query component has
   * been replaced with a given query string.
   *
   * @param uri The base URI.
   * @param query The new query component; may be {@code null} to delete the
   *     query component.
   * @return A suitably modified URI.
   */
  public static URI replaceUriQuery(URI uri, String query) {
    try {
      return new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(),
          uri.getPath(), query, uri.getFragment());
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Decodes an application/x-www-form-urlencoded format query string into its
   * component parameters.
   *
   * @param uri A URI to decode the query string of.
   * @return A multimap containing the decoded parameters from the uri.
   * @throws IllegalArgumentException if the URI's query isn't correctly formatted.
   */
  public static ListMultimap<String, String> decodeQueryString(URI uri) {
    return decodeQueryString(uri.getQuery());
  }

  /**
   * Decodes an application/x-www-form-urlencoded format query string into its
   * component parameters.
   *
   * @param string The query string to decode.
   * @return A multimap containing the decoded parameters from the string.
   * @throws IllegalArgumentException if the string isn't correctly formatted.
   */
  public static ListMultimap<String, String> decodeQueryString(String string) {
    ListMultimap<String, String> result = ArrayListMultimap.create();
    if (!Strings.isNullOrEmpty(string)) {
      for (String element : QUERY_SPLITTER.split(string)) {
        int index = element.indexOf('=');
        if (index < 0) {
          result.put(element, null);
        } else {
          result.put(element.substring(0, index), element.substring(index + 1));
        }
      }
    }
    return result;
  }

  /**
   * Encodes a multimap of query parameters in application/x-www-form-urlencoded
   * format.
   *
   * @param parameters The query parameters to be encoded.
   * @return The encoded string.
   */
  public static String encodeQueryString(Multimap<String, String> parameters) {
    StringBuilder builder = new StringBuilder();
    boolean needSeparator = false;
    for (Map.Entry<String, String> entry : parameters.entries()) {
      if (needSeparator) {
        builder.append('&');
      } else {
        needSeparator = true;
      }
      builder.append(entry.getKey());
      if (entry.getValue() != null) {
        builder.append('=');
        builder.append(entry.getValue());
      }
    }
    return builder.toString();
  }

  private static final Splitter QUERY_SPLITTER = Splitter.on('&');

  /**
   * Decodes an HTTP POST form submission in application/x-www-form-urlencoded
   * format.
   *
   * @param request An HTTP request to decode the body of.
   * @return A multimap containing the decoded parameters from the request.
   * @throws FormParameterCodingException if there are decoding errors.
   * @throws IOException if there are I/O errors.
   */
  @Nonnull
  public static ListMultimap<String, String> getPostParameters(HttpServletRequest request)
      throws FormParameterCodingException, IOException {
    String string
        = CharStreams.toString(
            new InputStreamReader(request.getInputStream(), ISO_8859_1));
    ListMultimap<String, String> decoded = ArrayListMultimap.create();
    if (string.isEmpty()) {
      return decoded;
    }
    SucceedResult result = POST_FORM_MATCHER.topLevelMatch(string);
    if (result == null) {
      throw new FormParameterCodingException(
          "Unable to parse form bindings: " + Stringify.object(string));
    }
    List<Object> objects = result.getState().getStack().toList();
    for (int i = 0; i < objects.size(); i += 2) {
      decoded.put(
          decodeFormString((String) objects.get(i)),
          decodeFormString((String) objects.get(i + 1)));
    }
    return decoded;
  }

  /**
   * An exception thrown when an HTTP POST form submission can't be decoded.
   */
  public static final class FormParameterCodingException extends Exception {
    private FormParameterCodingException(String message) {
      super(message);
    }
  }

  private static String decodeFormString(String string) {
    try {
      return URLDecoder.decode(string, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  private static Matcher buildPostFormMatcher() {
    Matcher matchHex
        = Matcher.oneOf(
            CharSet.builder()
            .add('0', '9' + 1)
            .add('A', 'F' + 1)
            .add('a', 'f' + 1)
            .build());
    Matcher matchChar
        = Matcher.alternatives(
            Matcher.oneOf(
                CharSet.builder()
                .add('0', '9' + 1)
                .add('A', 'Z' + 1)
                .add('a', 'z' + 1)
                .add("-_.!~*'()")  // "mark" characters (RFC 3875)
                .add(";/?:@+$,[]") // "reserved" characters except "&=" (RFC 3875)
                .build()),
            Matcher.sequence(
                Matcher.literal('%'),
                matchHex,
                matchHex));
    Matcher matchBinding
        = Matcher.sequence(
            matchChar.plus().pushMatchedString(),
            Matcher.alternatives(
                Matcher.sequence(
                    Matcher.literal('='),
                    matchChar.star().pushMatchedString()),
                Matcher.pushValue("")));
    return Matcher.sequence(
        Matcher.atStart(),
        matchBinding,
        Matcher.sequence(
            Matcher.literal('&'),
            matchBinding)
        .star(),
        Matcher.atEnd());
  }

  /**
   * Gets the URI for an HTTP request.
   *
   * @param request The HTTP request to get the URI from.
   * @param includeQuery If true, include the query part of the URI.
   * @return The request URI.
   * @throws IllegalArgumentException if the request's URI can't be parsed.
   */
  public static URI getRequestUri(HttpServletRequest request, boolean includeQuery) {
    URI uri = URI.create(request.getRequestURL().toString());
    return replaceUriQuery(uri, includeQuery ? request.getQueryString() : null);
  }

  /**
   * Gets the URL for an HTTP request.
   *
   * @param request The HTTP request to get the URL from.
   * @param includeQuery If true, include the query part of the URL.
   * @return The request URL.
   * @throws IllegalArgumentException if the request's URL can't be parsed.
   */
  public static URL getRequestUrl(HttpServletRequest request, boolean includeQuery) {
    try {
      return getRequestUri(request, includeQuery).toURL();
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Given a URL, gets a string suitable for logging.  This string omits the URL
   * query, as it might contain sensitive parameters that shouldn't be logged
   * (e.g. a password).  It also omits the fragment identifier, since that isn't
   * usually needed in the log.
   *
   * @param url The URL to get a log string for.
   * @return An appropriate string representation of the URL.
   */
  public static String getUrlLogString(URL url) {
    return getUriLogString(toUri(url));
  }

  /**
   * Given a URL string, gets a string suitable for logging.  This string omits
   * the URL query, as it might contain sensitive parameters that shouldn't be
   * logged (e.g. a password).  It also omits the fragment identifier, since
   * that isn't usually needed in the log.
   *
   * @param urlString The URL string to get a log string for.
   * @return An appropriate string representation of the URL.
   */
  public static String getUrlLogString(String urlString) {
    URI uri;
    try {
      uri = new URI(urlString);
    } catch (URISyntaxException e) {
      // Dumb, but in the unlikely event we get the exception, it should serve.
      int index = urlString.indexOf('?');
      return (index >= 0)
          ? urlString.substring(0, index)
          : urlString;
    }
    return getUriLogString(uri);
  }

  /**
   * Given a URI, gets a string suitable for logging.  This string omits the URI
   * query, as it might contain sensitive parameters that shouldn't be logged
   * (e.g. a password).  It also omits the fragment identifier, since that isn't
   * usually needed in the log.
   *
   * @param uri The URI to get a log string for.
   * @return An appropriate string representation of the URL.
   */
  public static String getUriLogString(URI uri) {
    try {
      return (new URI(uri.getScheme(), uri.getAuthority(), uri.getPath(), null, null))
          .toASCIIString();
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Gets the header value strings for any headers matching a given name.
   *
   * @param name The header name to look for.
   * @param request The request to look in.
   * @return The header values as an immutable list.
   */
  public static ImmutableList<String> getRequestHeaderValues(String name,
      HttpServletRequest request) {
    ImmutableList.Builder<String> builder = ImmutableList.builder();
    Enumeration<?> e = request.getHeaders(name);
    while (e.hasMoreElements()) {
      builder.add(String.class.cast(e.nextElement()));
    }
    return builder.build();
  }

  /**
   * Gets the content type of a request.
   *
   * @param request A request to get the content type of.
   * @return A parsed content-type structure.
   * @throws IllegalArgumentException if there are errors parsing the content-type header.
   */
  @Nonnull
  public static ContentType getRequestContentType(HttpServletRequest request) {
    String value = request.getHeader(HTTP_HEADER_CONTENT_TYPE);
    return (value != null)
        ? ContentType.parse(value)
        : DEFAULT_CONTENT_TYPE;
  }

  private static final ContentType DEFAULT_CONTENT_TYPE
      = new ContentType(DEFAULT_MIME_TYPE, DEFAULT_CHARSET);

  /**
   * A structured form of the content-type header for an HTTP message.
   */
  @Immutable
  @ParametersAreNonnullByDefault
  public static final class ContentType extends Writeable {
    @Nonnull private final String type;
    @Nonnull private final Charset charset;

    private ContentType(String type, Charset charset) {
      this.type = type;
      this.charset = charset;
    }

    /**
     * Makes a MIME content-type object.
     *
     * @param type The MIME type string, e.g. {@code "text/html"}.
     * @param charset The character set used in the message body.  If
     *     {@code null}, the default character set (ISO 8859-1) is used.
     * @return A content-type instance with the given components.
     * @throws IllegalArgumentException if the MIME type string isn't
     *     well-formed.
     */
    @Nonnull
    public static ContentType make(String type, @Nullable Charset charset) {
      Preconditions.checkArgument(type != null && isMimeTypeString(type));
      return new ContentType(type, (charset != null) ? charset : DEFAULT_CHARSET);
    }

    /**
     * Parses a content-type header-value string.
     *
     * @param string A header-value string.
     * @return A parsed content-type structure.
     * @throws IllegalArgumentException if there are errors parsing the given string.
     */
    @Nonnull
    public static ContentType parse(String string) {
      ParameterizedHeader parameterizedHeader = ParameterizedHeader.parse(string);
      String type = parameterizedHeader.getValue();
      if (!isMimeTypeString(type)) {
        return DEFAULT_CONTENT_TYPE;
      }
      for (Parameter parameter : parameterizedHeader.getParameters()) {
        if (PARAM_NAME_CHARSET.equalsIgnoreCase(parameter.getName())) {
          Charset charset;
          try {
            charset = Charset.forName(parameter.getValue());
          } catch (UnsupportedCharsetException e) {
            continue;
          }
          Preconditions.checkArgument(charset != null);
          return new ContentType(type, charset);
        }
      }
      return new ContentType(type, DEFAULT_CHARSET);
    }

    /**
     * Gets the MIME type for the HTTP message.
     */
    @Nonnull
    public String getType() {
      return type;
    }

    /**
     * Gets the character set for the HTTP message.
     */
    @Nonnull
    public Charset getCharset() {
      return charset;
    }

    @Override
    public void write(StringBuilder builder) {
      builder.append(type);
      builder.append(PARAM_SEPARATOR);
      writeParameter(PARAM_NAME_CHARSET, charset.name(), builder);
    }
  }

  /**
   * A structured representation of an HTTP header value with parameters.
   */
  @Immutable
  @ParametersAreNonnullByDefault
  public static final class ParameterizedHeader extends Writeable {
    @Nonnull private final String value;
    @Nonnull private final ImmutableList<Parameter> parameters;

    private ParameterizedHeader(String value, ImmutableList<Parameter> parameters) {
      this.value = value;
      this.parameters = parameters;
    }

    /**
     * Parses an HTTP header-value string with parameters.
     *
     * @param string A header-value string.
     * @return A parsed header-value structure.
     * @throws IllegalArgumentException if there are errors parsing the given string.
     */
    @Nonnull
    public static ParameterizedHeader parse(String string) {
      Iterator<String> iter = PARAM_SPLITTER.split(string).iterator();
      String value = iter.next();
      Preconditions.checkArgument(value != null);
      ImmutableList.Builder<Parameter> parametersBuilder = ImmutableList.builder();
      while (iter.hasNext()) {
        parametersBuilder.add(Parameter.parse(iter.next()));
      }
      return new ParameterizedHeader(value, parametersBuilder.build());
    }

    /**
     * Gets the base value of the HTTP header.
     */
    @Nonnull
    public String getValue() {
      return value;
    }

    /**
     * Gets the parameters of the HTTP header.
     */
    @Nonnull
    public ImmutableList<Parameter> getParameters() {
      return parameters;
    }

    @Override
    public void write(StringBuilder builder) {
      builder.append(value);
      for (Parameter parameter : parameters) {
        builder.append(PARAM_SEPARATOR);
        parameter.write(builder);
      }
    }
  }

  /**
   * A structured representation of an HTTP parameter.
   */
  @Immutable
  @ParametersAreNonnullByDefault
  public static final class Parameter extends Writeable {
    @Nonnull private final String name;
    @Nonnull private final String value;

    private Parameter(String name, String value) {
      this.name = name;
      this.value = value;
    }

    /**
     * Parses an HTTP parameter string.
     *
     * @param string A parameter string.
     * @return A parsed parameter structure.
     * @throws IllegalArgumentException if there are errors parsing the given string.
     */
    @Nonnull
    public static Parameter parse(String string) {
      int equals = string.indexOf(PARAM_VALUE_SEPARATOR);
      checkParameterArgument(equals >= 0, string);
      String name = string.substring(0, equals);
      checkParameterArgument(isHttpToken(name), string);
      String rawValue = string.substring(equals + 1);
      return new Parameter(name,
          isHttpToken(rawValue) ? rawValue : parseHttpQuotedString(rawValue));
    }

    private static void checkParameterArgument(boolean succeed, String argument) {
      Preconditions.checkArgument(succeed, "Incorrectly formatted HTTP parameter: %s", argument);
    }

    /**
     * Gets the parameter's name.
     */
    @Nonnull
    public String getName() {
      return name;
    }

    /**
     * Gets the parameter's value.
     */
    @Nonnull
    public String getValue() {
      return value;
    }

    @Override
    public void write(StringBuilder builder) {
      builder.append(name);
      builder.append(PARAM_VALUE_SEPARATOR);
      writeParameterValue(value, builder);
    }
  }

  /**
   * A base class that provides a {@link Object#toString} method based on a
   * method that writes an instance to a string builder.
   */
  @ParametersAreNonnullByDefault
  public abstract static class Writeable {
    @Override
    public String toString() {
      StringBuilder builder = new StringBuilder();
      write(builder);
      return builder.toString();
    }

    /**
     * Writes this object to a string builder.
     *
     * @param builder A string builder to write the object to.
     */
    public abstract void write(StringBuilder builder);
  }

  /**
   * Is the given string a MIME type?
   *
   * <p>This method only checks that the syntax is valid; it doesn't check
   * whether the type is registered with IETF.
   *
   * @param string The string to test.
   * @return True if the string is a valid MIME type.
   */
  public static boolean isMimeTypeString(String string) {
    int slash = string.indexOf("/");
    return (slash >= 0)
        && isHttpToken(string.substring(0, slash))
        && isHttpToken(string.substring(slash + 1));
  }

  /**
   * Parses an HTTP header parameter.  Parameters come in two forms:
   *
   * token PARAM_VALUE_SEPARATOR token
   * token PARAM_VALUE_SEPARATOR quoted-string
   *
   * The character set for a "token" is restricted.  A "quoted-string" is
   * surrounded by double quotes and can contain nearly all characters, plus
   * escaped characters.
   *
   * @param string The raw parameter string, assumed to have been trimmed of whitespace.
   * @return A list of two strings, the name and the value.
   * @throws IllegalArgumentException if the string can't be parsed.
   */
  public static List<String> parseHttpParameter(String string) {
    Parameter parameter = Parameter.parse(string);
    return ImmutableList.of(parameter.getName(), parameter.getValue());
  }

  /**
   * Is the given string an HTTP token?
   *
   * @param string The string to test.
   * @return True if the string is a valid HTTP token.
   */
  public static boolean isHttpToken(String string) {
    return !Strings.isNullOrEmpty(string) && TOKEN.matchesAllOf(string);
  }

  /**
   * Is the given string something that can be encoded as an HTTP quoted-string?
   *
   * @param string The string to test.
   * @return True if the string can be encoded using the quoted-string format.
   */
  public static boolean isQuotedStringEncodable(String string) {
    return string != null && TEXT.matchesAllOf(string);
  }

  /**
   * Encodes a string so that it's suitable as an HTTP parameter value.  In
   * other words, if the string is an HTTP token, it's self encoding.
   * Otherwise, it is converted to the quoted-string format.
   *
   * @param string The string to be encoded.
   * @return The same string encoded as an HTTP parameter value.
   * @throws IllegalArgumentException if the given string can't be encoded.
   */
  public static String makeHttpParameterValueString(String string) {
    if (isHttpToken(string)) {
      return string;
    }
    StringBuilder builder = new StringBuilder();
    writeQuotedString(string, builder);
    return builder.toString();
  }

  /**
   * Writes a string-valued HTTP parameter to a given string builder.  The
   * parameter is prefixed by {@link #PARAM_SEPARATOR}.
   *
   * @param name The parameter name, which must satisfy {@link #isHttpToken}.
   * @param value The parameter value, which must satisfy
   *     {@link #isQuotedStringEncodable}.
   * @param builder A string builder to write the parameter to.
   * @throws IllegalArgumentException if {@code name} or {@code value} can't be
   *     encoded.
   */
  public static void writeParameter(String name, String value, StringBuilder builder) {
    writeParameterName(name, builder);
    builder.append(PARAM_VALUE_SEPARATOR);
    writeParameterValue(value, builder);
  }

  /**
   * Writes a boolean-valued HTTP parameter to a given string builder.  The
   * parameter is prefixed by {@link #PARAM_SEPARATOR}.
   *
   * @param name The parameter name, which must satisfy {@link #isHttpToken}.
   * @param value The parameter value.
   * @param builder A string builder to write the parameter to.
   * @throws IllegalArgumentException if {@code name} can't be encoded.
   */
  public static void writeParameter(String name, boolean value, StringBuilder builder) {
    if (value) {
      writeParameterName(name, builder);
    }
  }

  /**
   * Writes an HTTP parameter name to a given string builder.  The name is
   * prefixed by {@link #PARAM_SEPARATOR}.
   *
   * @param name The parameter name, which must satisfy {@link #isHttpToken}.
   * @param builder A string builder to write the name to.
   * @throws IllegalArgumentException if {@code name} can't be encoded.
   */
  public static void writeParameterName(String name, StringBuilder builder) {
    Preconditions.checkArgument(isHttpToken(name));
    builder.append(PARAM_SEPARATOR);
    builder.append(name);
  }

  /**
   * Writes an HTTP parameter value to a given string builder.
   *
   * @param value The parameter value, which must satisfy
   *     {@link #isQuotedStringEncodable}.
   * @param builder A string builder to write the value to.
   * @throws IllegalArgumentException if {@code value} can't be encoded.
   */
  public static void writeParameterValue(String value, StringBuilder builder) {
    if (isHttpToken(value)) {
      builder.append(value);
    } else {
      writeQuotedString(value, builder);
    }
  }

  /**
   * Writes a string to a string builder in HTTP quoted-string format.
   *
   * @param string The string to be written.
   * @param builder A string builder to write the string to.
   * @throws IllegalArgumentException if {@code string} can't be encoded.
   */
  public static void writeQuotedString(String string, StringBuilder builder) {
    Preconditions.checkArgument(isQuotedStringEncodable(string),
        "String can't be encoded as an HTTP parameter value: %s", string);
    builder.append(STRING_DELIMITER);
    for (char c : string.toCharArray()) {
      if (c == STRING_QUOTE || c == STRING_DELIMITER) {
        builder.append(STRING_QUOTE);
      }
      builder.append(c);
    }
    builder.append(STRING_DELIMITER);
  }

  /**
   * Parses an HTTP quoted-string.
   *
   * @param string The string to parse.
   * @return The parsed value of the quoted string.
   * @throws IllegalArgumentException if the string isn't a valid quoted-string.
   */
  public static String parseHttpQuotedString(String string) {
    int end = string.length();
    checkQuotedStringArgument(
        (end >= 2
            && string.charAt(0) == STRING_DELIMITER
            && string.charAt(end - 1) == STRING_DELIMITER),
        string);
    StringBuilder builder = new StringBuilder();
    boolean pendingQuote = false;
    for (char c : string.substring(1, end - 1).toCharArray()) {
      if (pendingQuote) {
        pendingQuote = false;
        checkQuotedStringArgument(CHAR.matches(c), string);
        builder.append(c);
      } else if (c == STRING_QUOTE) {
        pendingQuote = true;
      } else {
        checkQuotedStringArgument(QDTEXT.matches(c), string);
        builder.append(c);
      }
    }
    checkQuotedStringArgument(!pendingQuote, string);
    return builder.toString();
  }

  /**
   * Gets the http range header value for requesting the first number of bytes.
   *
   * @param bytes The number of bytes to request.
   * @return The range header value
   */
  public static String getRangeString(int bytes) {
    return String.format(RANGE_FORMAT, bytes);
  }

  private static void checkQuotedStringArgument(boolean succeed, String argument) {
    Preconditions.checkArgument(succeed, "Incorrectly formatted quoted-string: %s", argument);
  }

  // These names are taken directly from RFC 2616.

  private static final CharMatcher OCTET = CharMatcher.inRange('\u0000', '\u00ff');

  // Not strictly correct: CHAR technically includes CR and LF, but only for
  // line folding.  Since we're looking at a post-line-folding string, they
  // shouldn't be present.
  private static final CharMatcher CHAR =
      difference(CharMatcher.ascii(), CharMatcher.anyOf("\n\r"));

  /** ASCII control characters. */
  public static final CharMatcher CTLS =
      CharMatcher.inRange('\u0000', '\u001f').or(CharMatcher.is('\u007f'));

  /** ASCII alphabetic characters. */
  public static final CharMatcher ALPHA =
      CharMatcher.anyOf("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

  /** ASCII digit characters. */
  public static final CharMatcher DIGIT = CharMatcher.anyOf("0123456789");

  /** Linear white space. */
  public static final CharMatcher LWS = CharMatcher.anyOf(" \t");

  /** Plain text. */
  public static final CharMatcher TEXT = union(difference(OCTET, CTLS), LWS);

  // Text that can be included in a quoted-string without backquotes.  Note that
  // RFC 2616 specifies only '"' as an exception, but clearly '\\' needs to be
  // excepted as well.
  private static final CharMatcher QDTEXT = difference(TEXT, CharMatcher.anyOf("\"\\"));

  // Separator characters that aren't allowed in most places except inside
  // quoted-strings.
  private static final CharMatcher SEPARATORS = CharMatcher.anyOf("()<>@,;:\\\"/[]?={} \t");

  // The constituent characters of a token.
  private static final CharMatcher TOKEN = difference(CharMatcher.ascii(), union(CTLS, SEPARATORS));

  private static CharMatcher union(CharMatcher m1, CharMatcher m2) {
    return m1.or(m2);
  }

  private static CharMatcher difference(CharMatcher m1, CharMatcher m2) {
    return m1.and(m2.negate());
  }

  // HTTP date formats (from RFC 2616):
  //
  // HTTP-date    = rfc1123-date | rfc850-date | asctime-date
  // rfc1123-date = wkday "," SP date1 SP time SP "GMT"
  // rfc850-date  = weekday "," SP date2 SP time SP "GMT"
  // asctime-date = wkday SP date3 SP time SP 4DIGIT
  // date1        = 2DIGIT SP month SP 4DIGIT
  //                ; day month year (e.g., 02 Jun 1982)
  // date2        = 2DIGIT "-" month "-" 2DIGIT
  //                ; day-month-year (e.g., 02-Jun-82)
  // date3        = month SP ( 2DIGIT | ( SP 1DIGIT ))
  //                ; month day (e.g., Jun  2)
  // time         = 2DIGIT ":" 2DIGIT ":" 2DIGIT
  //                ; 00:00:00 - 23:59:59
  // wkday        = "Mon" | "Tue" | "Wed"
  //              | "Thu" | "Fri" | "Sat" | "Sun"
  // weekday      = "Monday" | "Tuesday" | "Wednesday"
  //              | "Thursday" | "Friday" | "Saturday" | "Sunday"
  // month        = "Jan" | "Feb" | "Mar" | "Apr"
  //              | "May" | "Jun" | "Jul" | "Aug"
  //              | "Sep" | "Oct" | "Nov" | "Dec"

  private static final String DATE_FORMAT_RFC1123 = "EEE, dd MMM yyyy HH:mm:ss zzz";
  private static final String DATE_FORMAT_RFC850 = "EEEE, dd-MMM-yy HH:mm:ss zzz";
  private static final String DATE_FORMAT_ASCTIME = "EEE MMM dd HH:mm:ss yyyy";

  /**
   * Generates an HTTP date string.
   *
   * @param date A date value specified as a non-negative difference from the
   *     epoch in milliseconds.
   * @return An HTTP date string representing that date.
   */
  public static String generateHttpDate(long date) {
    return getDateFormat(DATE_FORMAT_RFC1123).format(new Date(date));
  }

  /**
   * Parses an HTTP date string.
   *
   * @param dateString The string to parse.
   * @return The difference, measured in milliseconds, between the specified
   *     date and 1970-01-01T00:00:00Z.
   * @throws IllegalArgumentException if the date string can't be parsed.
   */
  public static long parseHttpDate(String dateString) {
    try {
      return parseDate(DATE_FORMAT_RFC1123, dateString);
    } catch (ParseException e) {
      // Fall through to next format.
    }
    try {
      return parseDate(DATE_FORMAT_RFC850, dateString);
    } catch (ParseException e) {
      // Fall through to next format.
    }
    try {
      return parseDate(DATE_FORMAT_ASCTIME, dateString);
    } catch (ParseException e) {
      throw new IllegalArgumentException("Can't parse as HTTP date string: " + dateString);
    }
  }

  private static long parseDate(String formatString, String dateString)
      throws ParseException {
    return getDateFormat(formatString).parse(dateString).getTime();
  }

  private static DateFormat getDateFormat(String formatString) {
    DateFormat format = new SimpleDateFormat(formatString);
    format.setCalendar(Calendar.getInstance(GMT, Locale.US));
    return format;
  }

  private static final TimeZone GMT = TimeZone.getTimeZone("GMT");

  /**
   * Is the given string a valid domain name?  Uses a fairly restrictive
   * definition, corresponding to the "preferred syntax" of RFC 1034 as updated
   * by RFC 1123.
   *
   * @param string The string to be tested.
   * @return True only if the string is a valid domain name.
   */
  public static boolean isValidDomainName(String string) {
    return parseDomainName(string) != null;
  }

  /**
   * Converts a given domain name to its canonical form.  This should eventually
   * handle IDNA names, but for now we just canonicalize case.
   *
   * @param domainName The domain name to convert.
   * @return The canonical form for {@code domainName}.
   * @throws IllegalArgumentException if {@code domainName} doesn't satisfy
   *     {@code #isValidDomainName}.
   */
  public static String canonicalizeDomainName(String domainName) {
    List<String> labels = parseDomainName(domainName);
    Preconditions.checkArgument(labels != null, "Not a valid domain name: %s", domainName);
    return labelsToDomanName(labels);
  }

  /**
   * Gets the "parent domain" name of a domain name.
   *
   * @param domainName The domain name to get the parent domain name of.
   * @return The parent domain name, or {@code null} if there isn't one.
   * @throws IllegalArgumentException if {@code domainName} doesn't satisfy
   *     {@code #isValidDomainName}.
   */
  public static String domainNameParent(String domainName) {
    List<String> labels = parseDomainName(domainName);
    Preconditions.checkArgument(labels != null, "Not a valid domain name: %s", domainName);
    if (labels.size() < 2) {
      return null;
    }
    labels.remove(0);
    return labelsToDomanName(labels);
  }

  private static List<String> parseDomainName(String domainName) {
    if (!(domainName.length() >= 1 && domainName.length() <= 255)) {
      return null;
    }
    List<String> labels = Lists.newArrayList(DOMAIN_NAME_SPLITTER.split(domainName));
    if (!(labels.size() >= 1 && labels.size() <= 127)) {
      return null;
    }
    for (String label : labels) {
      if (!isValidDomainLabel(label)) {
        return null;
      }
    }
    // Eliminates IPv4 addresses:
    if (DIGIT.matchesAllOf(labels.get(labels.size() - 1))) {
      return null;
    }
    return labels;
  }

  private static boolean isValidDomainLabel(String label) {
    return label.length() >= 1
        && label.length() <= 63
        && DOMAIN_LABEL_CHAR.matchesAllOf(label)
        && label.charAt(0) != '-'
        && label.charAt(0) != '_'
        && label.charAt(label.length() - 1) != '-'
        && label.charAt(label.length() - 1) != '_';
  }

  private static String labelsToDomanName(List<String> labels) {
    return DOMAIN_NAME_JOINER.join(
        Iterables.transform(labels,
            new Function<String, String>() {
              @Override
              public String apply(String label) {
                return label.toLowerCase(Locale.US);
              }
            }));
  }

  // allow underscores b/15127606
  private static final CharMatcher DOMAIN_LABEL_CHAR = ALPHA.or(DIGIT)
      .or(CharMatcher.is('-')).or(CharMatcher.is('_'));
  private static final Splitter DOMAIN_NAME_SPLITTER = Splitter.on('.');
  private static final Joiner DOMAIN_NAME_JOINER = Joiner.on('.');

  /**
   * Compare two URLs for equality.  Preferable to using the {@link URL#equals}
   * because the latter calls out to DNS and can block.
   *
   * @param url1 A URL to compare.
   * @param url2 Another URL to compare.
   * @return True if the two URLs are the same.
   */
  public static boolean areUrlsEqual(@Nullable URL url1, @Nullable URL url2) {
    if (url1 == null || url2 == null) {
      return url1 == null && url2 == null;
    }
    return areStringsEqualIgnoreCase(url1.getProtocol(), url2.getProtocol())
        && areStringsEqualIgnoreCase(url1.getHost(), url2.getHost())
        && url1.getPort() == url2.getPort()
        && areStringsEqual(url1.getFile(), url2.getFile())
        && areStringsEqual(url1.getRef(), url2.getRef());
  }

  private static boolean areStringsEqual(String s1, String s2) {
    return s1 == s2 || ((s1 == null) ? s2 == null : s1.equals(s2));
  }

  private static boolean areStringsEqualIgnoreCase(String s1, String s2) {
    return s1 == s2 || ((s1 == null) ? s2 == null : s1.equalsIgnoreCase(s2));
  }

  /**
   * @return A URI builder with default scheme and host arguments.
   */
  public static UriBuilder uriBuilder() {
    return new UriBuilder("http", "google.com");
  }

  /**
   * @param scheme The URI Scheme to use.
   * @param host The URI host to use.
   * @return A URI builder with the given scheme and host.
   */
  public static UriBuilder uriBuilder(String scheme, String host) {
    Preconditions.checkNotNull(scheme);
    Preconditions.checkNotNull(host);
    return new UriBuilder(scheme, host);
  }

  /**
   * A class to build URIs by incrementally specifying their path segments.
   */
  public static final class UriBuilder {
    private final String scheme;
    private final String host;
    private final StringBuilder pathBuilder;

    private UriBuilder(String scheme, String host) {
      this.scheme = scheme;
      this.host = host;
      pathBuilder = new StringBuilder();
    }

    /**
     * Add a segment to the path being accumulated.
     *
     * @param segment The segment to add.
     * @return The builder, for convenience.
     * @throws IllegalArgumentException if the segment contains any illegal characters.
     */
    public UriBuilder addSegment(String segment) {
      Preconditions.checkArgument(segment != null && !segment.contains("/"),
          "Path segments may not contain the / character: %s", segment);
      pathBuilder.append("/").append(segment);
      return this;
    }

    /**
     * Add a hex-encoded random segment to the path being accumulated.
     *
     * @param nBytes The number of random bytes in the segment.
     * @return The builder, for convenience.
     */
    public UriBuilder addRandomSegment(int nBytes) {
      return addSegment(SecurityManagerUtil.generateRandomNonceHex(nBytes));
    }

    /**
     * @return The URI composed of the accumulated parts.
     * @throws IllegalArgumentException if there's a syntax problem with one of the parts.
     */
    public URI build() {
      try {
        return new URI(scheme, host, pathBuilder.toString(), null);
      } catch (URISyntaxException e) {
        throw new IllegalArgumentException(e);
      }
    }
  }

  private static UriBuilder gsaUriBuilder() {
    // In multibox, the authority id will be shared among different machines
    // so remove the specific gsa id here.
    return uriBuilder()
        .addSegment("enterprise")
        .addSegment("gsa");
  }

  public static UriBuilder smUriBuilder() {
    return gsaUriBuilder()
        .addSegment("security-manager");
  }
}
