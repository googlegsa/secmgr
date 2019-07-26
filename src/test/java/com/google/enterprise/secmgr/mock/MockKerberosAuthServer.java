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

package com.google.enterprise.secmgr.mock;

import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.common.Base64;
import com.google.enterprise.secmgr.common.Base64DecoderException;
import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.ServletBase;

import java.io.IOException;
import java.io.Writer;
import java.util.Enumeration;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class implements a HTTP service that requires kerberos authentication.
 */
@Immutable
public class MockKerberosAuthServer extends ServletBase
    implements GettableHttpServlet, PostableHttpServlet, MockServer {
  private static final Logger logger = Logger.getLogger(MockKerberosAuthServer.class.getName());

  private final String contextUrl;
  private final String sampleUrl;
  private final ImmutableList<String> validMessages;

  public MockKerberosAuthServer(String contextUrl, ImmutableList<String> validMessages) {
    this.contextUrl = contextUrl;
    this.sampleUrl = contextUrl + "/sample";
    this.validMessages = validMessages;
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
  }

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String header = getAuthCredentials(request);
    if (header == null) {
      unauthorizedResponse(response);
      return;
    }

    if (validMessages.contains(header)) {
      Writer w = initNormalResponse(response);
      w.write("<html><head><title>You've won!!!</title></head><body>\n");
      w.write("<p>You are the lucky winner of our content!!!</p>\n");
      w.write("</body></html>\n");
      w.close();
    } else {
      unauthorizedResponse(response);
    }
  }

  private void unauthorizedResponse(HttpServletResponse response)
      throws IOException {
    response.addHeader("WWW-Authenticate", "Negotiate");
    response.addHeader("WWW-Authenticate", "NTLM");
    initErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED);
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    doGet(request, response);
  }

  /**
   * Parse request header "Authorization"
   * @param request the http request.
   * @return the kerberos message. Return null if there is no valid kerbero message.
   */
  private static String getAuthCredentials(HttpServletRequest request) {
    Enumeration<?> headers = request.getHeaders("Authorization");
    if (headers == null || !headers.hasMoreElements()) {
      return null;
    }

    // Deal with only the first "Authorization" header
    String[] parts = String.class.cast(headers.nextElement()).split(" ");
    if (!(parts.length == 2
            && ("NTLM".equalsIgnoreCase(parts[0])
                || "Negotiate".equalsIgnoreCase(parts[0])))) {
      return null;
    }
    logger.info("kerberos Auth header: " + parts[1]);
    byte[] decoded;
    try {
      decoded = Base64.decode(parts[1]);
      return parts[1];
    } catch (Base64DecoderException e) {
      return null;
    }
  }
}
