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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.enterprise.secmgr.common.Base64;
import com.google.enterprise.secmgr.common.Base64DecoderException;
import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.common.ServletBase;
import java.io.IOException;
import java.io.Writer;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Formatter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import jcifs.ntlmssp.NtlmMessage;
import jcifs.ntlmssp.Type1Message;
import jcifs.ntlmssp.Type2Message;
import jcifs.ntlmssp.Type3Message;

/**
 * This class implements a HTTP service that requires NTLM authentication.
 */
public class MockNtlmAuthServer extends ServletBase
    implements GettableHttpServlet, PostableHttpServlet, MockServer {
  private static final Logger logger = Logger.getLogger(MockNtlmAuthServer.class.getName());

  private final String contextUrl;
  private final String sampleUrl;
  private final byte[] serverChallenge;
  private final ImmutableMap<String, String> passwordMap;
  private Type2Message myChallenge;

  public MockNtlmAuthServer(String contextUrl, byte[] serverChallenge,
      ImmutableMap<String, String> passwordMap) {
    Preconditions.checkNotNull(serverChallenge);
    Preconditions.checkArgument(serverChallenge.length == 8);
    Preconditions.checkNotNull(passwordMap);
    this.contextUrl = contextUrl;
    this.sampleUrl = (contextUrl != null) ? contextUrl + "/sample" : null;
    this.serverChallenge = serverChallenge;
    this.passwordMap = passwordMap;
    System.setProperty("jcifs.smb.lmCompatibility", "2");
    reset();
  }

  public MockNtlmAuthServer(String contextUrl, ImmutableMap<String, String> passwordMap) {
    this(contextUrl, SecurityManagerUtil.generateRandomNonce(8), passwordMap);
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
    myChallenge = null;
  }

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    DecodedHeader header = getAuthCredentials(request);
    if (header == null) {
      unauthorizedResponse(response);
      return;
    }

    if (header.message instanceof Type1Message) {
      myChallenge = new Type2Message((Type1Message) header.message, serverChallenge, null);
      response.addHeader("WWW-Authenticate",
          header.keyword + " " + Base64.encode(myChallenge.toByteArray()));
      initErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED);
    } else if (verifyResponse(Type3Message.class.cast(header.message))) {
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
   * @return type of NTLM message parsed
   */
  private static DecodedHeader getAuthCredentials(HttpServletRequest request) {
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
    logger.info("NTLM Auth header: " + parts[1]);
    byte[] decoded;
    try {
      decoded = Base64.decode(parts[1]);
    } catch (Base64DecoderException e) {
      return null;
    }

    // Is this a Type 1 message?
    NtlmMessage inMessage;
    try {
      return new DecodedHeader(parts[0], new Type1Message(decoded));
    } catch (IOException e) {
      // not a Type 1
    }
    try {
      return new DecodedHeader(parts[0], new Type3Message(decoded));
    } catch (IOException e) {
      // not a Type 3 either
    }
    logger.info("Could not parse Authorization header");
    return null;
  }

  private static class DecodedHeader {
    public final String keyword;
    public final NtlmMessage message;

    public DecodedHeader(String keyword, NtlmMessage message) {
      this.keyword = keyword;
      this.message = message;
    }
  }

  private boolean verifyResponse(Type3Message response) {
    try {
      byte[] lmResp = response.getLMResponse();
      byte[] ntResp = response.getNTResponse();
      String password = passwordMap.get(response.getUser());
      byte[] lmResp0 = Type3Message.getLMResponse(myChallenge, password);
      byte[] ntResp0 = Type3Message.getNTResponse(myChallenge, password);
      if (lmResp0 != null) {
        logger.info("Expected LM response: " + bytesToHex(lmResp0));
      }
      if (lmResp != null) {
        logger.info("Actual LM response: " + bytesToHex(lmResp));
      }
      if (ntResp0 != null) {
        logger.info("Expected NT response: " + bytesToHex(ntResp0));
      }
      if (ntResp != null) {
        logger.info("Actual NT response: " + bytesToHex(ntResp));
      }
      if (!Arrays.equals(ntResp, ntResp0)) {
        return false;
      }
      if (Arrays.equals(lmResp, ntResp0) || Arrays.equals(lmResp, lmResp0)) {
        return true;
      }
      logger.warning("Wrong response of Type 3 for user " + response.getUser());
      return false;
    } catch (Exception e) {
      logger.log(Level.WARNING, "Caught: ", e);
      return false;
    }
  }

  private String bytesToHex(byte[] bytes) {
    Formatter f = new Formatter();
    for (byte b : bytes) {
      f.format("%02x", b);
    }
    return f.toString();
  }
}
