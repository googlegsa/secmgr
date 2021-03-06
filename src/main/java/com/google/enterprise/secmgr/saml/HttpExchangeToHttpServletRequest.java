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

package com.google.enterprise.secmgr.saml;

import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.http.HttpExchange;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;
import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.ReadListener;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;

/**
 * A converter that converts an {@link HttpExchange} object, making it look like a {@link
 * HttpServletRequest} object. This allows response messages to be processed using the OpenSAML
 * library.
 */
public class HttpExchangeToHttpServletRequest implements HttpServletRequest {

  private final HttpExchange exchange;
  private final ByteArrayInputStream entityStream;

  public HttpExchangeToHttpServletRequest(HttpExchange exchange) throws IOException {
    this.exchange = exchange;
    entityStream = new ByteArrayInputStream(exchange.getResponseEntityAsByteArray());
  }

  @Override
  public ServletInputStream getInputStream() throws IOException {
    entityStream.reset();
    return new ServletInputStream() {
      @Override
      public int read() throws IOException {
        return entityStream.read();
      }

      @Override
      public int read(byte[] b, int off, int len) throws IOException {
        return entityStream.read(b, off, len);
      }

      @Override
      public boolean isFinished() {
        throw new UnsupportedOperationException();
      }

      @Override
      public boolean isReady() {
        throw new UnsupportedOperationException();
      }

      @Override
      public void setReadListener(ReadListener readListener) {
        throw new UnsupportedOperationException();
      }
    };
  }

  @Override
  public String getHeader(String name) {
    return exchange.getResponseHeaderValue(name);
  }

  @Override
  public String getMethod() {
    return exchange.getHttpMethod();
  }

  @Override
  public String getAuthType() {
    throw new UnsupportedOperationException();
  }

  @Override
  public Cookie[] getCookies() {
    throw new UnsupportedOperationException();
  }

  @Override
  public long getDateHeader(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Enumeration<String> getHeaders(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Enumeration<String> getHeaderNames() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int getIntHeader(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getPathInfo() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getPathTranslated() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getContextPath() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getQueryString() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getRemoteUser() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean isUserInRole(String role) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Principal getUserPrincipal() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getRequestedSessionId() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getRequestURI() {
    throw new UnsupportedOperationException();
  }

  @Override
  public StringBuffer getRequestURL() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getServletPath() {
    throw new UnsupportedOperationException();
  }

  @Override
  public HttpSession getSession(boolean create) {
    throw new UnsupportedOperationException();
  }

  @Override
  public HttpSession getSession() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean isRequestedSessionIdValid() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean isRequestedSessionIdFromCookie() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean isRequestedSessionIdFromURL() {
    throw new UnsupportedOperationException();
  }

  @Deprecated
  @Override
  public boolean isRequestedSessionIdFromUrl() {
    throw new UnsupportedOperationException();
  }

  @Override
  public Object getAttribute(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Enumeration<String> getAttributeNames() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getCharacterEncoding() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void setCharacterEncoding(String env) throws UnsupportedEncodingException {}

  @Override
  public int getContentLength() {
    return Integer.parseInt(exchange.getRequestHeaderValue(HttpUtil.HTTP_HEADER_CONTENT_LENGTH));
  }

  @Override
  public String getContentType() {
    return exchange.getRequestHeaderValue(HttpUtil.HTTP_HEADER_CONTENT_TYPE);
  }

  @Override
  public String getParameter(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Enumeration<String> getParameterNames() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String[] getParameterValues(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Map<String, String[]> getParameterMap() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getProtocol() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getScheme() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getServerName() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int getServerPort() {
    throw new UnsupportedOperationException();
  }

  @Override
  public BufferedReader getReader() throws IOException {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getRemoteAddr() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getRemoteHost() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void setAttribute(String name, Object o) {}

  @Override
  public void removeAttribute(String name) {}

  @Override
  public Locale getLocale() {
    throw new UnsupportedOperationException();
  }

  @Override
  public Enumeration<Locale> getLocales() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean isSecure() {
    return false;
  }

  @Override
  public RequestDispatcher getRequestDispatcher(String path) {
    throw new UnsupportedOperationException();
  }

  @Deprecated
  @Override
  public String getRealPath(String path) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int getRemotePort() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getLocalName() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getLocalAddr() {
    throw new UnsupportedOperationException();
  }

  @Override
  public int getLocalPort() {
    throw new UnsupportedOperationException();
  }

  @Override
  public long getContentLengthLong() {
    throw new UnsupportedOperationException();
  }

  @Override
  public ServletContext getServletContext() {
    throw new UnsupportedOperationException();
  }

  @Override
  public AsyncContext startAsync() throws IllegalStateException {
    throw new UnsupportedOperationException();
  }

  @Override
  public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse)
      throws IllegalStateException {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean isAsyncStarted() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean isAsyncSupported() {
    throw new UnsupportedOperationException();
  }

  @Override
  public AsyncContext getAsyncContext() {
    throw new UnsupportedOperationException();
  }

  @Override
  public DispatcherType getDispatcherType() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String changeSessionId() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {
    throw new UnsupportedOperationException();
  }

  @Override
  public void login(String username, String password) throws ServletException {
    throw new UnsupportedOperationException();
  }

  @Override
  public void logout() throws ServletException {
    throw new UnsupportedOperationException();
  }

  @Override
  public Collection<Part> getParts() throws IOException, ServletException {
    throw new UnsupportedOperationException();
  }

  @Override
  public Part getPart(String name) throws IOException, ServletException {
    throw new UnsupportedOperationException();
  }

  @Override
  public <T extends HttpUpgradeHandler> T upgrade(Class<T> handlerClass)
      throws IOException, ServletException {
    throw new UnsupportedOperationException();
  }
}
