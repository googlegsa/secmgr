// Copyright 2008 Google Inc.
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

package com.google.enterprise.secmgr.mock;

import static com.google.enterprise.secmgr.common.SessionUtil.GSA_SESSION_ID_COOKIE_NAME;

import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.common.Base64;
import com.google.enterprise.secmgr.common.CookieStore;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HttpTransport;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.HttpUtil.ContentType;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.StringPair;
import com.google.enterprise.secmgr.http.HttpClientInterface;
import com.google.enterprise.secmgr.http.HttpExchange;
import com.google.enterprise.secmgr.http.HttpExchangeContext;
import com.google.enterprise.secmgr.testing.ServletTestUtil;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.annotation.Nonnull;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;

/**
 * A mock instance of HttpClientInterface, using HttpTransport for transport.
 */
public class MockHttpClient implements HttpClientInterface {
  private static final Logger logger = Logger.getLogger(MockHttpClient.class.getName());

  private final HttpTransport transport;
  private final MockHttpSession session;
  private final CookieStore clientCookies;
  private String referrer;
  private boolean fillInBoilerplateHeaders;

  private String secMgrSessionId;

  public MockHttpClient(HttpTransport transport) {
    this(transport, null);
  }

  public MockHttpClient(HttpTransport transport, CookieStore clientCookies) {
    this.transport = transport;
    this.clientCookies = clientCookies;
    session = new MockHttpSession();
    referrer = null;
    fillInBoilerplateHeaders = false;
  }

  public String getSecMgrSessionId() {
    return secMgrSessionId;
  }

  public void setSecMgrSessionId(String secMgrSessionId) {
    this.secMgrSessionId = secMgrSessionId;
  }

  public void setFillInBoilerplateHeaders(boolean fillInBoilerplateHeaders) {
    this.fillInBoilerplateHeaders = fillInBoilerplateHeaders;
  }

  // For debugging:
  public MockHttpSession getSession() {
    return session;
  }

  @Override
  public HttpExchange headExchange(URL url) {
    MockHttpServletRequest request = ServletTestUtil.makeMockHttpHead(null, url.toString());
    addQueryParameters(url, request);
    return new MockExchange(request, url);
  }

  @Override
  public HttpExchange getExchange(URL url) {
    MockHttpServletRequest request = ServletTestUtil.makeMockHttpGet(null, url.toString());
    addQueryParameters(url, request);
    return new MockExchange(request, url);
  }

  @Override
  public HttpExchange getExchange(URL url, int length) {
    Preconditions.checkArgument(length >= 0);
    HttpExchange exchange = getExchange(url);
    exchange.setRequestHeader(HttpUtil.HTTP_HEADER_RANGE, HttpUtil.getRangeString(length));
    return exchange;
  }

  @Override
  public HttpExchange getExchange(URL url, HttpExchangeContext context) {
    // TODO: implement this for testing
    return getExchange(url);
  }

  @Override
  public HttpClientInterface newSingleUseInstance() {
    return this;
  }

  private void addQueryParameters(URL url, MockHttpServletRequest request) {
    String query = url.getQuery();
    if (query != null) {
      for (String param : Splitter.on('&').trimResults().split(query)) {
        int e = param.indexOf('=');
        if (e < 0) {
          request.addParameter(param, "");
        } else {
          request.addParameter(param.substring(0, e).trim(), param.substring(e + 1).trim());
        }
      }
    }
  }

  @Override
  public HttpExchange postExchange(URL url, ListMultimap<String, String> parameters) {
    MockHttpServletRequest request = ServletTestUtil.makeMockHttpPost(null, url.toString());
    if (parameters != null) {
      for (String name : parameters.keySet()) {
        for (String value : parameters.get(name)) {
          request.addParameter(name, value);
        }
      }
    }
    return new MockExchange(request, url);
  }

  @Override
  public HttpExchange newHttpExchange(URL url) {
    return getExchange(url);
  }

  /**
   * A mock implementation of an HTTP exchange object.
   */
  public class MockExchange implements HttpExchange {

    private final MockHttpServletRequest request;
    private final URL url;
    private final CookieStore exchangeCookies;
    private final ListMultimap<String, String> requestHeaders;
    private MockHttpServletResponse response;
    private String credentials;
    private boolean followRedirects;

    public MockExchange(MockHttpServletRequest request, URL url) {
      this.request = request;
      this.url = url;
      exchangeCookies = (clientCookies != null) ? clientCookies : GCookie.makeStore();
      requestHeaders = ArrayListMultimap.create();
      credentials = null;
      followRedirects = false;
    }

    @Override
    public void setBasicAuthCredentials(String username, String password) {
      credentials = "Basic " + Base64.encode((username + ":" + password).getBytes());
    }

    @Override
    public void setFollowRedirects(boolean followRedirects) {
      this.followRedirects = followRedirects;
    }

    @Override
    public void setTimeout(int timeout) {
    }

    @Override
    public String getHttpMethod() {
      return request.getMethod();
    }

    @Override
    public URL getUrl() {
      return url;
    }

    @Override
    public void addParameter(String name, String value) {
      request.addParameter(name, value);
    }

    @Override
    public void setRequestHeader(String name, String value) {
      if (HttpUtil.HTTP_HEADER_COOKIE.equalsIgnoreCase(name)) {
        throw new IllegalArgumentException("setRequestHeader cannot be used for cookies.");
      }
      if (HttpUtil.HTTP_HEADER_AUTHORIZATION.equalsIgnoreCase(name)) {
        credentials = value;
      }
      requestHeaders.removeAll(name);
      requestHeaders.put(name, value);
    }

    @Override
    public List<String> getRequestHeaderValues(String headerName) {
      return requestHeaders.get(headerName);
    }

    @Override
    public String getRequestHeaderValue(String headerName) {
      List<String> values = getRequestHeaderValues(headerName);
      return values.isEmpty() ? null : values.get(0);
    }

    @Override
    public void addCookies(Iterable<GCookie> newCookies) {
      for (GCookie cookie : newCookies) {
        exchangeCookies.add(cookie);
      }
    }

    @Override
    @Nonnull
    public CookieStore getCookies() {
      return exchangeCookies;
    }

    @Override
    public void setRequestBody(byte[] requestContent) {
      request.setContent(requestContent);
    }

    @Override
    public int exchange() throws IOException {
      if (HttpUtil.HTTP_METHOD_POST.equalsIgnoreCase(request.getMethod())
          && request.getParameterNames().hasMoreElements()) {
        ServletTestUtil.generatePostContent(request);
      }
      MockHttpServletResponse response = exchange1(request);
      if (followRedirects) {
        while (isRedirect(response)) {
          requestHeaders.clear();
          response = exchange1(ServletTestUtil.makeMockHttpGet(null, getRedirectUrl(response)));
        }
      }
      return response.getStatus();
    }

    public void setKerberosCredential(String credential) {
      this.credentials = credential;
    }

    private boolean isRedirect(MockHttpServletResponse response) {
      return ServletBase.isRedirectStatus(response.getStatus());
    }

    private String getRedirectUrl(MockHttpServletResponse response) {
      return String.class.cast(response.getHeader(HttpUtil.HTTP_HEADER_LOCATION));
    }

    private MockHttpServletResponse exchange1(MockHttpServletRequest request)
        throws IOException {

      // Make sure that request is filled in.
      if (fillInBoilerplateHeaders) {
        for (StringPair sp : HttpUtil.getBoilerplateHeaders()) {
          setRequestHeader(sp.getName(), sp.getValue());
        }
      }
      if (referrer != null) {
        setRequestHeader(HttpUtil.HTTP_HEADER_REFERRER, referrer);
      }
      if (credentials != null) {
        setRequestHeader(HttpUtil.HTTP_HEADER_AUTHORIZATION, credentials);
        logger.info("Adding authorization response header " + credentials);
      }
      if (request.getContentLength() >= 0) {
        setRequestHeader(HttpUtil.HTTP_HEADER_CONTENT_LENGTH,
            Integer.toString(request.getContentLength()));
      }
      request.setSession(session);

      // Add any relevant cookies to the request.
      // Only add those cookies that are applicable to the request URL.
      CookieStore toSend = GCookie.makeStore();
      for (GCookie cookie : exchangeCookies) {
        if (cookie.isGoodFor(HttpUtil.toUri(url)) || cookie.getName().equals(GSA_SESSION_ID_COOKIE_NAME)) {
          toSend.add(cookie);
        }
      }

      if (CollectionUtils.isNotEmpty(toSend)) {
        request.setCookies(toSend.stream().map(cookie -> cookie.toCookie()).toArray(Cookie[]::new));
      }

      // Add the headers to the request.
      for (Map.Entry<String, String> entry : requestHeaders.entries()) {
        request.addHeader(entry.getKey(), entry.getValue());
      }

      ContentType contentType;
      try {
        contentType = HttpUtil.getRequestContentType(request);
      } catch (IllegalArgumentException e) {
        logger.warning("Unable to parse Content-Type header: " + e.getMessage());
        contentType = null;
      }
      if (contentType != null) {
        request.setContentType(contentType.getType());
        request.setCharacterEncoding(contentType.getCharset().name());
      }

      // Do the exchange.
      MockHttpServletResponse response = new MockHttpServletResponse();
      try {
        transport.exchange(request, response);
      } catch (ServletException e) {
        IOException ee = new IOException();
        ee.initCause(e);
        throw ee;
      }
      this.response = response;

      if (response.getHeaders("Set-Cookie").stream()
          .anyMatch(cookieStr -> cookieStr.startsWith(GSA_SESSION_ID_COOKIE_NAME + "="))) {
        logger.info("Got session: " + response.getCookie(GSA_SESSION_ID_COOKIE_NAME).getValue());
        secMgrSessionId = response.getCookie(GSA_SESSION_ID_COOKIE_NAME).getValue();
      }
      referrer = HttpUtil.getRequestUrl(request, false).toString();

      // Save the response cookies.
      // need synchronized here to protect "exchangeCookies" collection because this method is used
      // in tests that run several threads and exchangeCookies is not thread-safe
      // e.g. (com.google.enterprise.secmgr.servlets.AuthnServletTest.testConcurrentForSameUser)
      synchronized (exchangeCookies) {
        GCookie.parseResponseHeaders(
            getResponseHeaderValues(HttpUtil.HTTP_HEADER_SET_COOKIE),
            HttpUtil.toUri(url),
            exchangeCookies);
      }

      // Make sure the content length is properly recorded.
      int length = response.getContentAsByteArray().length;
      response.setContentLength(length);
      if (!response.containsHeader(HttpUtil.HTTP_HEADER_CONTENT_LENGTH)) {
        response.addHeader(HttpUtil.HTTP_HEADER_CONTENT_LENGTH, String.valueOf(length));
      }

      return response;
    }

    @Override
    public String getResponseEntityAsString() throws IOException {
      return response.getContentAsString();
    }

    @Override
    public InputStream getResponseEntityAsStream() {
      return new ByteArrayInputStream(response.getContentAsByteArray());
    }

    @Override
    public byte[] getResponseEntityAsByteArray() {
      return response.getContentAsByteArray();
    }

    @Override
    public String getResponseCharSet() {
      return response.getCharacterEncoding();
    }

    @Override
    public String getResponseHeaderValue(String name) {
      return String.class.cast(response.getHeader(name));
    }

    @Override
    public ListMultimap<String, String> getResponseHeaders() {
      ImmutableListMultimap.Builder<String, String> builder = ImmutableListMultimap.builder();
      for (Object rawName : response.getHeaderNames()) {
        String name = String.class.cast(rawName);
        for (Object value : response.getHeaders(name)) {
          builder.put(name.toLowerCase(), String.class.cast(value));
        }
      }
      return builder.build();
    }

    @Override
    public List<String> getResponseHeaderValues(String name) {
      List<String> result = Lists.newArrayList();
      for (Object value : response.getHeaders(name)) {
        result.add(String.class.cast(value));
      }
      return result;
    }

    @Override
    public int getStatusCode() {
      return response.getStatus();
    }

    @Override
    public void close() {
    }   
  }
}
