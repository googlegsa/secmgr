/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.enterprise.secmgr.servlets;

import com.google.common.io.Files;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.ExportedState;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.http.HttpExchange;
import com.google.enterprise.secmgr.mock.MockHttpClient;
import com.google.enterprise.secmgr.mock.MockHttpTransport;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;

/**
 * Test the CommandsServlet class
 */
public class CommandsServletTest extends SecurityManagerTestCase {

  private CommandsServlet commandsServlet;
  private MockHttpTransport transport;
  private MockHttpClient client;
  private HttpExchange exchange;
  private URL secmgrUrl;
  private String urlString = "http://secmgr.example.com";
  private String testSessionId1 = "4156029ff937c3a4f120e4b41ac00015";
  private String jsonAuthnInfo = "";
  private AuthnSession authnSession;
  private AuthnSessionManager authnsm;

  @Override
  public void setUp() throws Exception {
    super.setUp();

    File configFile = FileUtil.getContextFile("AuthNInfo.json");
    jsonAuthnInfo = Files.asCharSource(configFile, Charset.defaultCharset()).read();

    commandsServlet = CommandsServlet.makeTestInstance();

    //Initialize transport
    transport = ConfigSingleton.getInstance(MockHttpTransport.class);
    secmgrUrl = new URL(urlString);
    client = new MockHttpClient(transport);

    transport.registerServlet(urlString, commandsServlet,
        MockHttpTransport.ServletCapabilities.GETTABLE_AND_POSTABLE);

    authnsm = ConfigSingleton.getInstance(AuthnSessionManager.class);

    authnSession = AuthnSession.newInstance(testSessionId1);
    authnSession.importSessionState(AuthnSessionState.empty());
    authnsm.saveSession(authnSession);

    exchange = client.postExchange(secmgrUrl, null);
  }

  public void testClearCache() throws IOException {
    String requestBody = "<Commands><ClearCache>true</ClearCache></Commands>";
    String responseBody = executeRequest(requestBody);
    assertEquals(
        "<CommandResponse>\n<ClearCache>SUCCESS</ClearCache>\n" + "</CommandResponse>\n",
        responseBody);
  }

  public void testGetAuthNInfo() throws IOException {

    ExportedState serverState = ExportedState.fromJsonString(jsonAuthnInfo);
    authnSession.importSessionState(serverState.getSessionState());
    authnsm.saveSession(authnSession);

    String requestBody = "<Commands><GetAuthNInfo></GetAuthNInfo><SessionId>"
      + testSessionId1 + "</SessionId></Commands>";

    String responseBody = executeRequest(requestBody);
    ExportedState returnedState = ExportedState.fromJsonString(responseBody);

    // The "instructions" on the state solely define a state.
    // So the equality of instructions guarantees the equality of session state
    assertEquals(serverState.getSessionState().getInstructions(),
        returnedState.getSessionState().getInstructions());
  }

  public void testSetAuthNInfo() throws IOException {

    assertTrue(authnSession.getSnapshot().getState().isEmpty());

    String requestBody = "<Commands><SetAuthNInfo>" + jsonAuthnInfo
      + "</SetAuthNInfo><SessionId>" + testSessionId1 + "</SessionId></Commands>";
    String responseBody = executeRequest(requestBody);

    AuthnSession mostRecentSessionState = authnsm.findSessionById(testSessionId1);
    assertTrue(!mostRecentSessionState.getSnapshot().getState().isEmpty());
  }

  private String executeRequest(String requestBody) throws IOException{
    exchange.setRequestBody(requestBody.getBytes());
    int status = exchange.exchange();
    assertTrue(HttpUtil.isGoodHttpStatus(status));
    return exchange.getResponseEntityAsString();
  }
}
