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

package com.google.enterprise.secmgr.testing;

import com.google.enterprise.secmgr.common.HttpUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.util.Enumeration;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Useful utilities for SAML testing.
 */
public final class ServletTestUtil {

  public static MockHttpServletRequest makeMockHttpGet(String clientUrl, String serverUrl) {
    return makeMockHttpRequest("GET", clientUrl, serverUrl);
  }

  public static MockHttpServletRequest makeMockHttpPost(String clientUrl, String serverUrl) {
    return makeMockHttpRequest("POST", clientUrl, serverUrl);
  }

  public static MockHttpServletRequest makeMockHttpHead(String clientUrl, String serverUrl) {
    return makeMockHttpRequest("HEAD", clientUrl, serverUrl);
  }

  private static MockHttpServletRequest makeMockHttpRequest(String method, String client,
      String server) {
    URI serverUri = URI.create(server);
    // TODO: figure out how to get servlet context from serverUrl.
    MockHttpServletRequest request = new MockHttpServletRequest(null, method, serverUri.getPath());
    request.setQueryString(serverUri.getRawQuery());
    request.setScheme(serverUri.getScheme());
    request.setServerName(serverUri.getHost());
    request.setServerPort(serverUri.getPort());
    for (Map.Entry<String, String> entry : HttpUtil.decodeQueryString(serverUri).entries()) {
      request.addParameter(entry.getKey(), entry.getValue());
    }
    if (client != null) {
      URI clientUri = URI.create(client);
      request.setRemoteHost(clientUri.getHost());
      request.setRemotePort(clientUri.getPort());
    }
    {
      String host = serverUri.getHost();
      int port = serverUri.getPort();
      request.addHeader("Host", (port < 0) ? host : String.format("%s:%d", host, port));
    }
    return request;
  }

  public static String servletRequestToString(HttpServletRequest request, String tag)
      throws IOException {
    StringWriter out = new StringWriter();
    out.write(tag);
    out.write(":\n");
    writeServletRequest(request, out);
    String result = out.toString();
    out.close();
    return result;
  }

  public static void writeServletRequest(HttpServletRequest request, Writer out)
      throws IOException {
    writeRequestLine(request, out);
    writeRequestHeaders(request, out);
    copyText(request.getReader(), out);
  }

  private static void writeRequestLine(HttpServletRequest request, Writer out) throws IOException {
    out.write(request.getMethod());
    out.write(" ");
    out.write(request.getRequestURI());
    {
      String qs = request.getQueryString();
      if (qs != null) {
        out.write("?");
        out.write(qs);
      }
    }
    out.write(" ");
    out.write("HTTP/1.1");
    out.write("\n");
  }

  @SuppressWarnings("unchecked")
  private static void writeRequestHeaders(HttpServletRequest request, Writer out)
      throws IOException {
    for (Enumeration<String> names = request.getHeaderNames(); names.hasMoreElements();) {
      String name = names.nextElement();
      for (Enumeration<String> values = request.getHeaders(name); values.hasMoreElements();) {
        out.write(name);
        out.write(": ");
        out.write(values.nextElement());
        out.write("\n");
      }
    }
    out.write("\n");
  }

  public static String servletResponseToString(MockHttpServletResponse response, String tag)
      throws IOException {
    StringWriter out = new StringWriter();
    out.write(tag);
    out.write(":\n");
    writeServletResponse(response, out);
    String result = out.toString();
    out.close();
    return result;
  }

  public static void writeServletResponse(MockHttpServletResponse response, Writer out)
      throws IOException {
    {
      String url = response.getRedirectedUrl();
      if (url != null) {
        response.setStatus(HttpServletResponse.SC_SEE_OTHER);
        response.setHeader("Location", url);
      }
    }
    writeResponseLine(response, out);
    writeResponseHeaders(response, out);
    copyText(getResponseReader(response), out);
  }

  public static Reader getResponseReader(MockHttpServletResponse response) {
    return new InputStreamReader(
        new ByteArrayInputStream(response.getContentAsByteArray()),
        getResponseCharset(response));
  }

  public static Charset getResponseCharset(MockHttpServletResponse response) {
    try {
      return Charset.forName(response.getCharacterEncoding());
    } catch (IllegalCharsetNameException e) {
      return HttpUtil.DEFAULT_CHARSET;
    } catch (IllegalArgumentException e) {
      return HttpUtil.DEFAULT_CHARSET;
    }
  }

  private static void writeResponseLine(MockHttpServletResponse response, Writer out)
      throws IOException {
    out.write("HTTP/1.1");
    out.write(" ");
    out.write(String.format("%03d", response.getStatus()));
    out.write(" ");
    out.write("insert reason here");
    out.write("\n");
  }

  @SuppressWarnings("unchecked")
  private static void writeResponseHeaders(MockHttpServletResponse response, Writer out)
      throws IOException {
    for (String name : response.getHeaderNames()) {
      for (Object value : response.getHeaders(name)) {
        out.write(name);
        out.write(": ");
        out.write(String.valueOf(value));
        out.write("\n");
      }
    }
    out.write("\n");
  }

  private static void copyText(Reader in, Writer out) throws IOException {
    char[] buffer = new char[0x1000];
    while (true) {
      int nRead = in.read(buffer);
      if (nRead < 1) {
        break;
      }
      out.write(buffer, 0, nRead);
    }
  }

  /**
   * Generate POST body and headers for a mock servlet request.
   *
   * Should be called immediately before the servlet is called.  Converts the mock's
   * parameters into the appropriate form for an HTTP message.  Wouldn't be needed if the
   * mock was more complete.
   *
   * @param request The request to be filled in.
   */
  public static void generatePostContent(MockHttpServletRequest request) throws IOException {
    ByteArrayOutputStream bs = new ByteArrayOutputStream();
    Writer out = new OutputStreamWriter(bs);
    writePostParams(request, out);
    byte[] content = bs.toByteArray();
    out.close();
    request.setContent(content);
    request.setContentType("application/x-www-form-urlencoded");
    request.setCharacterEncoding("UTF-8");
    request.addHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
    request.addHeader("Content-Length", Integer.valueOf(content.length).toString());
  }

  private static void writePostParams(HttpServletRequest request, Writer out) throws IOException {
    @SuppressWarnings("unchecked") Enumeration<String> keys = request.getParameterNames();
    boolean atStart = true;
    while (keys.hasMoreElements()) {
      String key = keys.nextElement();
      String[] values = request.getParameterValues(key);
      for (int i = 0; i < values.length; i += 1) {
        if (atStart) {
          atStart = false;
        } else {
          out.write("&");
        }
        out.write(key);
        out.write("=");
        out.write(values[i]);
      }
    }
    out.flush();
  }

  /**
   * Return a "valid" HTTP status code when responding to a given request.
   * Basically, if there's a "range" header, the result is 206.
   */
  public static int goodHttpStatusFor(HttpServletRequest request) {
    return (request.getHeader("Range") != null)
        ? HttpServletResponse.SC_PARTIAL_CONTENT
        : HttpServletResponse.SC_OK;
  }
}
