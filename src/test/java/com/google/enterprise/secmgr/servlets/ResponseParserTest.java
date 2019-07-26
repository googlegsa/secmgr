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
package com.google.enterprise.secmgr.servlets;

import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.modules.SamlAuthnClient;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Response;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class ResponseParserTest extends SecurityManagerTestCase {
  
  private static final String TESTDATA_PATH = FileUtil.getContextDirectory();
  private static final String RESPONSE_FILE = "saml-response.xml";
  private static final String RECEPIENT = "https://entzg12.hot/security-manager"
      + "/samlassertionconsumer";

  private UnmarshallerFactory unmarshallerFactory;
  private BasicParserPool parser;

  public ResponseParserTest() throws InitializationException {
    // Since we don't use OpenSamlUtil here, we need to bootstrap OpenSaml library.
    InitializationService.initialize();
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    XMLObjectProviderRegistrySupport.getMarshallerFactory();
    unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    parser = new BasicParserPool();
    parser.setNamespaceAware(true);
    parser.initialize();
  }

  public void testParseResponse() throws Exception {
    Response response = buildResponseFromFile();
    SamlAuthnClient client = createSamlAuthnClient(response);
    DateTime now = response.getAssertions().get(0).getConditions().getNotBefore();

    ResponseParser subject = ResponseParser.makeForTest(client, RECEPIENT, response, "sessionId",
        now.getMillis());

    boolean result = subject.areAssertionsValid();

    assertTrue(result);
  }

  public void testParseResponseWithMissingNotOnOrAfter() throws Exception {
    Response response = buildResponseFromFile();
    SamlAuthnClient client = createSamlAuthnClient(response);
    Conditions conditions = response.getAssertions().get(0).getConditions();
    DateTime now = conditions.getNotBefore();
    conditions.setNotOnOrAfter(null);

    ResponseParser subject = ResponseParser.makeForTest(client, RECEPIENT, response, "sessionId",
        now.getMillis());

    boolean result = subject.areAssertionsValid();

    assertTrue(result);
  }

  public void testParseResponseWithInvalidNotOnOrAfter() throws Exception {
    Response response = buildResponseFromFile();
    SamlAuthnClient client = createSamlAuthnClient(response);
    Conditions conditions = response.getAssertions().get(0).getConditions();
    DateTime now = conditions.getNotBefore();
    conditions.setNotOnOrAfter(now.minusMinutes(1));

    ResponseParser subject = ResponseParser.makeForTest(client, RECEPIENT, response, "sessionId",
        now.getMillis());

    boolean result = subject.areAssertionsValid();

    assertFalse(result);
  }
  
  private void setClientRequestId(SamlAuthnClient client, String requestId) {
      try {
        Field requestIdField = SamlAuthnClient.class.getDeclaredField("requestId");
        requestIdField.setAccessible(true);
        
        Field modifiers = Field.class.getDeclaredField("modifiers");
        modifiers.setAccessible(true);
        modifiers.setInt(requestIdField, requestIdField.getModifiers() & ~Modifier.FINAL);
        
        requestIdField.set(client, requestId);
      } catch (Exception e) {
        fail("Cannot set requestId on SamlAuthnClient: reflection failed.");
      }
  }

  private SamlAuthnClient createSamlAuthnClient(Response response) throws IOException {
    SamlSharedData sharedData = SamlSharedData.make(
        "http://google.com/enterprise/gsa/T3-FCYP38T39YSGY",
        SamlSharedData.Role.SERVICE_PROVIDER, null);
    SamlAuthnClient client = SamlAuthnClient.make(Metadata.getInstanceForTest(
        "http://foobar.org/saml-idp-2"), response.getIssuer().getValue(), sharedData);
    setClientRequestId(client, "_f23e7216b92a743de52e086a962b90ae");
    return client;
  }

  private Response buildResponseFromFile() throws Exception {
    InputStream in = new FileInputStream(new File(TESTDATA_PATH, RESPONSE_FILE));

    Document doc = parser.parse(in);
    Element samlElement = doc.getDocumentElement();
    in.close();

    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElement);
    return (Response) unmarshaller.unmarshall(samlElement);
  }
}
