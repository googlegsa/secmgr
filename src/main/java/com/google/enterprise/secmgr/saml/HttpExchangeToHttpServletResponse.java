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

import com.google.common.base.Strings;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.http.HttpExchange;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Collection;
import java.util.Locale;
import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

/**
 * A converter that converts an {@link HttpExchange} object, making it look like an OpenSAML {@link
 * HttpServletResponse} object. This allows request messages to be generated using the OpenSAML
 * library.
 */
public class HttpExchangeToHttpServletResponse implements HttpServletResponse {

  private final HttpExchange exchange;
  private final ByteArrayOutputStream outputStream;

  public HttpExchangeToHttpServletResponse(HttpExchange exchange) {
    this.exchange = exchange;
    outputStream = new ByteArrayOutputStream();
  }
  
  public void finish() {
    exchange.setRequestBody(outputStream.toByteArray());
  }

  @Override
  public void setHeader(String name, String value) {
    exchange.setRequestHeader(name, value);
  }

  @Override
  public void addHeader(String name, String value) {
    exchange.setRequestHeader(name, value);
  }

  @Override
  public void setIntHeader(String name, int value) {
    exchange.setRequestHeader(name, String.valueOf(value));
  }

  @Override
  public void addIntHeader(String name, int value) {
    exchange.setRequestHeader(name, String.valueOf(value));
  }

  @Override
  public void setCharacterEncoding(String encoding) {}

  @Override
  public void addCookie(Cookie cookie) {
    exchange.addCookies(Arrays.asList(GCookie.builder(cookie).build()));
  }

  @Override
  public boolean containsHeader(String name) {
    return !Strings.nullToEmpty(exchange.getRequestHeaderValue(name)).trim().isEmpty();
  }

  @Override
  public String encodeURL(String url) {
    throw new UnsupportedOperationException();
  }

  @Override
  public String encodeRedirectURL(String url) {
    throw new UnsupportedOperationException();
  }

  @Deprecated
  @Override
  public String encodeUrl(String url) {
    throw new UnsupportedOperationException();
  }

  @Deprecated
  @Override
  public String encodeRedirectUrl(String url) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void sendError(int sc, String msg) throws IOException {}

  @Override
  public void sendError(int sc) throws IOException {}

  @Override
  public void sendRedirect(String location) throws IOException {}

  @Override
  public void setDateHeader(String name, long date) {}

  @Override
  public void addDateHeader(String name, long date) {}

  @Override
  public void setStatus(int sc) {}

  @Deprecated
  @Override
  public void setStatus(int sc, String sm) {}

  @Override
  public void setContentLength(int len) {}

  @Override
  public void setContentType(String type) {}

  @Override
  public void setBufferSize(int size) {}

  @Override
  public int getBufferSize() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void flushBuffer() throws IOException {}

  @Override
  public void resetBuffer() {}

  @Override
  public boolean isCommitted() {
    throw new UnsupportedOperationException();
  }

  @Override
  public void reset() {}

  @Override
  public void setLocale(Locale loc) {}

  @Override
  public Locale getLocale() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getCharacterEncoding() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getContentType() {
    throw new UnsupportedOperationException();
  }

  @Override
  public ServletOutputStream getOutputStream() throws IOException {
    return new ServletOutputStream() {

      @Override
      public void write(int b) throws IOException {
        outputStream.write(b);
      }

      @Override
      public void close() {
        finish();
      }

      @Override
      public boolean isReady() {
        throw new UnsupportedOperationException();
      }

      @Override
      public void setWriteListener(WriteListener writeListener) {
        throw new UnsupportedOperationException();
      }
    };
  }

  @Override
  public PrintWriter getWriter() throws IOException {
    throw new UnsupportedOperationException();
  }

  @Override
  public void setContentLengthLong(long len) {
    throw new UnsupportedOperationException();
  }

  @Override
  public int getStatus() {
    throw new UnsupportedOperationException();
  }

  @Override
  public String getHeader(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Collection<String> getHeaders(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Collection<String> getHeaderNames() {
    throw new UnsupportedOperationException();
  }
}
