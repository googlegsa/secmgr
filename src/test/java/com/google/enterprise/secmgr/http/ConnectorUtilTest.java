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
package com.google.enterprise.secmgr.http;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.io.ByteStreams;
import com.google.common.io.CharStreams;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.XmlUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.mock.MockHttpClient;
import com.google.enterprise.secmgr.mock.MockHttpTransport;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.enterprise.sessionmanager.SessionFilter;
import java.io.IOException;
import java.io.Writer;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.w3c.dom.Document;

/**
 * Unit tests for {@link ConnectorUtil}.
 */
public class ConnectorUtilTest extends SecurityManagerTestCase {
  private static final Logger logger = Logger.getLogger(ConnectorUtilTest.class.getName());

  private static final String TAG_NAME
      = "\u6625\u8282\u56DE\u5BB6\u8DEF\u00B7\u6625\u8FD0\u5B8C\u5168\u624B\u518C";
  private static final String EXPECTED_STRING = "<" + TAG_NAME + "/>";
  private static final byte[] EXPECTED_BYTES = EXPECTED_STRING.getBytes(UTF_8);
  private static final String CM_URL
      = "http://myConnectorManager1.example.com" + ConnectorUtil.CM_AUTHENTICATE_SERVLET_PATH;

  private final XmlUtil xmlUtil;

  public ConnectorUtilTest() {
    xmlUtil = XmlUtil.getInstance();
  }

  public void testDocumentEncoding()
      throws IOException {
    Document document = xmlUtil.makeDocument(null, TAG_NAME, null);
    byte[] actualBytes = ConnectorUtil.documentToBytes(document);
    assertEquals(Arrays.toString(EXPECTED_BYTES), Arrays.toString(actualBytes));
  }

  public void testSendMessageEncoding1()
      throws IOException, ServletException {
    trySendMessageEncoding(false);
  }

  public void testSendMessageEncoding2()
      throws IOException, ServletException {
    trySendMessageEncoding(true);
  }

  private void trySendMessageEncoding(boolean useReader)
      throws IOException, ServletException {
    MockHttpTransport httpTransport = new MockHttpTransport(ConfigSingleton
        .getInstance(SessionFilter.class));
    HttpServlet servlet = new FakeCm(useReader);
    httpTransport.registerServlet(CM_URL, servlet);
    MockHttpClient httpClient = new MockHttpClient(httpTransport);
    HttpClientUtil.setHttpClient(httpClient);
    Document document = xmlUtil.makeDocument(null, TAG_NAME, null);
    ConnectorUtil.sendRequest(document, CM_URL, -1);
  }

  private static final class FakeCm extends ServletBase implements PostableHttpServlet {
    final boolean useReader;

    FakeCm(boolean useReader) {
      this.useReader = useReader;
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
        throws IOException {
      try {
        String actualString = readAll(request);
        Writer writer
            = initNormalResponse(response,
                EXPECTED_STRING.equals(actualString)
                ? HttpServletResponse.SC_OK
                : HttpServletResponse.SC_BAD_REQUEST);
        try {
          writer.write("Expected: ");
          writer.write(EXPECTED_STRING);
          writer.write("\nActual: ");
          writer.write(actualString);
          writer.write("\n");
        } finally {
          writer.close();
        }
      } catch (IOException e) {
        logger.log(Level.WARNING, "Exception while processing request: ", e);
        throw e;
      } catch (RuntimeException e) {
        logger.log(Level.WARNING, "Exception while processing request: ", e);
        throw e;
      }
    }

    String readAll(HttpServletRequest request)
        throws IOException {
      return useReader
          ? CharStreams.toString(request.getReader())
          : new String(ByteStreams.toByteArray(request.getInputStream()), UTF_8);
    }
  }
}
