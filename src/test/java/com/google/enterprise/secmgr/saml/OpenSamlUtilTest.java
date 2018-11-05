// Copyright 2014 Google Inc.
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

import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.File;
import java.io.FileReader;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;

/**
 * Unit tests for the {@link OpenSamlUtil} class.
 */
public class OpenSamlUtilTest extends SecurityManagerTestCase {

  private static final String SAML_MSG_WITH_DOCTYPE = "/saml-message-with-doctype.xml";
  private static final String SAML_MSG_WITHOUT_DOCTYPE = "/saml-message-without-doctype.xml";

  /**
   * Test that the parser returned by OpenSamlUtil can accept both saml message with or without
   * doctype.
   */
  public void testParsingSamlMessageWithBasicParserAcceptBoth() throws Exception {
    FileReader samlWithoutDoctype =
        new FileReader(new File(getClass().getResource(SAML_MSG_WITHOUT_DOCTYPE).getFile()));
    FileReader samlWithDoctype =
        new FileReader(getClass().getResource(SAML_MSG_WITH_DOCTYPE).getFile());

    BasicParserPool parserPoolAcceptDoctype = OpenSamlUtil.getBasicParserPoolInternal(
        /*acceptDTD=*/true);
    parserPoolAcceptDoctype.parse(samlWithoutDoctype);
    parserPoolAcceptDoctype.parse(samlWithDoctype);

    samlWithoutDoctype.close();
    samlWithDoctype.close();
  }

  /**
   * Test that the parser returned by OpenSamlUtil can accept saml message without doctype and
   * decline saml message with doctype.
   */
  public void testParsingSamlMessageWithBasicParserDeclineDoctype() throws Exception {
    FileReader samlWithoutDoctype =
        new FileReader(getClass().getResource(SAML_MSG_WITHOUT_DOCTYPE).getFile());
    FileReader samlWithDoctype =
        new FileReader(getClass().getResource(SAML_MSG_WITH_DOCTYPE).getFile());

    BasicParserPool parserPoolNotAcceptDoctype = OpenSamlUtil.getBasicParserPoolInternal(
        /*acceptDTD=*/false);
    parserPoolNotAcceptDoctype.parse(samlWithoutDoctype);
    try {
      parserPoolNotAcceptDoctype.parse(samlWithDoctype);
      fail("fail to decline saml message with doctype");
    } catch (XMLParserException e) {
      // pass
    }

    samlWithoutDoctype.close();
    samlWithDoctype.close();
  }
}
