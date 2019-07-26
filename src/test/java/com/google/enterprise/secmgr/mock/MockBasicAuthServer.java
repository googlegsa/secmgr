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

import com.google.common.collect.Maps;
import com.google.enterprise.secmgr.common.Base64;
import com.google.enterprise.secmgr.common.Base64DecoderException;
import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.StringPair;
import com.google.enterprise.secmgr.testing.ServletTestUtil;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A base class for implementing mock HTTP BASIC authentication servers.
 */
public abstract class MockBasicAuthServer extends ServletBase
    implements GettableHttpServlet, PostableHttpServlet, MockServer, LaggardServer {
  private static final Logger LOGGER = Logger.getLogger(MockBasicAuthServer.class.getName());

  private final String contextUrl;
  private final String sampleUrl;
  private final String realm;
  protected final Map<String, String> passwordMap;

  private long delayMillis = 0; // Artificial slowing down of request handling.

  protected MockBasicAuthServer(String contextUrl, String realm) {
    this.contextUrl = contextUrl;
    this.sampleUrl = contextUrl + "/sample";
    this.realm = realm;
    passwordMap = Maps.newHashMap();
  }

  @Override
  public void addToIntegration(MockIntegration integration)
      throws ServletException {
    MockHttpTransport transport = integration.getHttpTransport();
    transport.registerContextUrl(contextUrl);
    transport.registerServlet(sampleUrl, this);
  }

  @Override
  public String getContextUrl() {
    return contextUrl;
  }

  @Override
  public String getSampleUrl() {
    return sampleUrl;
  }

  @Override
  public void reset() {
    delayMillis = 0;
  }

  @Override
  public void setDelayMillis(long delayMillis) {
    this.delayMillis = delayMillis;
  }

  @Override
  public long getDelayMillis() {
    return this.delayMillis;
  }

  /**
   * A mock HTTP BASIC server.
   */
  public static class Server1 extends MockBasicAuthServer {
    public Server1(String contextUrl) {
      super(contextUrl, "Server1");
      passwordMap.put("user1", "test1");
      passwordMap.put("joe", "plumber");
      passwordMap.put("chinese客人", "test1");
    }
  }

  /**
   * A different mock HTTP BASIC server that uses different credentials.
   */
  public static class Server2 extends MockBasicAuthServer {
    public Server2(String contextUrl) {
      super(contextUrl, "Server2");
      passwordMap.put("joe", "biden");
    }
  }

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    if (delayMillis > 0) {
      try {
        Thread.sleep(delayMillis);
      } catch (InterruptedException e) {
        throw new IllegalStateException("Unexpected interruption of test", e);
      }
    }
    if (!goodAuthCredential(request, passwordMap, realm)) {
      response.addHeader(HttpUtil.HTTP_HEADER_WWW_AUTHENTICATE, "Basic realm=\"" + realm + "\"");
      initErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED);
      return;
    }
    Writer w = initNormalResponse(response, ServletTestUtil.goodHttpStatusFor(request));
    w.write("<html><head><title>You've won!!!</title></head><body>\n");
    w.write("<p>You are the lucky winner of our content!!!</p>\n");
    w.write("</body></html>\n");
    w.close();
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    doGet(request, response);
  }

  public static String getValidAuthCredential(HttpServletRequest request,
      Map<String, String> passwordMap, String realm) {
    List<StringPair> credentials = getAuthCredentials(request);
    for (StringPair credential : credentials) {
      LOGGER.info("BasicAuth credential: " + credential.getName() + ":"
                  + credential.getValue() + " realm: " + realm + " expects: "
                  + passwordMap.get(credential.getName()));
      if (credential.getValue().equals(passwordMap.get(credential.getName()))) {
        return credential.getName();
      }
    }
    return null;
  }

  private static boolean goodAuthCredential(HttpServletRequest request,
      Map<String, String> passwordMap, String realm) {
    return null != getValidAuthCredential(request, passwordMap, realm);
  }

  private static List<StringPair> getAuthCredentials(HttpServletRequest request) {
    @SuppressWarnings("unchecked")
    Enumeration<String> headers = request.getHeaders(HttpUtil.HTTP_HEADER_AUTHORIZATION);
    List<StringPair> result = new ArrayList<StringPair>();
    while (headers.hasMoreElements()) {
      String value = headers.nextElement();
      List<StringPair> credentials = parseAuthorizationHeader(value);
      if (credentials != null) {
        result.addAll(credentials);
      }
    }
    return result;
  }

  private static List<StringPair> parseAuthorizationHeader(String header) {
    String h = header.trim();
    if (!h.regionMatches(true, 0, "BASIC ", 0, 6)) {
      return null;
    }
    LOGGER.info("BasicAuth header: " + h);
    List<StringPair> credentials = new ArrayList<StringPair>();
    for (String param : h.substring(6).trim().split("[, \t]*,[, \t]*")) {
      try {
        String decoded = new String(Base64.decode(param.getBytes()), "UTF-8");
        int colon = decoded.indexOf(':');
        if (colon < 0) {
          return null;
        }
        credentials.add(new StringPair(decoded.substring(0, colon),
                                       decoded.substring(colon + 1)));
      } catch (Base64DecoderException e) {
        return null;
      } catch (UnsupportedEncodingException e) {
        return null;
      }
    }
    return credentials;
  }
}
