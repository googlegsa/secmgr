// Copyright 2018 Google Inc.
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

import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.ServletBase;

import java.io.IOException;
import java.io.Writer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Mock implementaion of File system gateway.
 * 
 */
public class MockFileSystemGatewayServer extends ServletBase
    implements GettableHttpServlet, PostableHttpServlet, MockServer {
  
  private final String url;
  private final String sessionId;
  private final String username;
  private final String domain;
  private final String password;
  

  public MockFileSystemGatewayServer(String url, String sessionId, String username, 
      String domain, String password) {
    this.url = url;
    this.username = username;
    this.domain = domain;
    this.password = password;
    this.sessionId = sessionId;
  }
  
  @Override
  public void addToIntegration(MockIntegration integration)
      throws ServletException {
    MockHttpTransport transport = integration.getHttpTransport();
    transport.registerServlet(url, this);
  }
  
  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String sessionIdParam =
        request.getParameter("sessionId");
    String usernameParam =
        request.getParameter("username");
    String passwordParam =
        request.getParameter("password");
    String domainParam =
        request.getParameter("domain");
    if (sessionIdParam.equals(this.sessionId) ||
        (usernameParam.equals(this.username) && domainParam.equals(this.domain) &&
         passwordParam.equals(this.password))) {
      Writer w = initNormalResponse(response);
      w.write("<html><head><title>You've won!!!</title></head><body>\n");
      w.write("<p>You are the lucky winner of our content!!!</p>\n");
      w.write("</body></html>\n");
      w.close();
    } else {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    doGet(request, response);
  }

  @Override
  public String getContextUrl() {
    return url;
  }

  @Override
  public String getSampleUrl() {
    return url;
  }

  @Override
  public void reset() {    
  }
}
