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
package com.google.enterprise.secmgr.common;

import static com.google.common.base.Charsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.google.common.io.Files;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

@RunWith(JUnit4.class)
public class XmlUtilTest {
  @Rule public TemporaryFolder tempFolder = new TemporaryFolder();

  private File tempFile;

  @Before
  public void setUp() throws IOException {
    tempFile = tempFolder.newFile("test.txt");
    Files.asCharSink(tempFile, UTF_8).write("hello, world");
  }

  @Test
  public void verifyTempFile() throws IOException {
    assertEquals("hello, world", Files.asCharSource(tempFile, UTF_8).readFirstLine());
  }

  /** Confirms that XML parsing is working. */
  @Test
  public void readXmlDocument() throws IOException {
    String xml = "<?xml version=\"1.0\"?>"
        + "<root xmlns=\"foo\" xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
        + "<element param=\"abcde\"><child param2=\"555\" param3=\"1234\">text"
        + "</child></element><anotherElement>Content</anotherElement>"
        + "</root>";

    Document doc = XmlUtil.getInstance().readXmlDocument(new StringReader(xml));
    assertNotNull(doc);
    Element root = doc.getDocumentElement();
    assertEquals("textContent", root.getTextContent());
  }

  /** Confirms that XML external entities are not resolved. */
  @Test
  public void readXmlDocument_xxe() throws IOException {
    String xml = "<!DOCTYPE foo ["
        + "<!ENTITY bar SYSTEM \"file://" + tempFile + "\">"
        + "]>"
        + "<root>&bar;</root>";

    Document doc = XmlUtil.getInstance().readXmlDocument(new StringReader(xml));
    assertNotNull(doc);
    Element root = doc.getDocumentElement();
    assertEquals("", root.getTextContent());
  }

  /** Confirms that XML external includes are not processed. */
  @Test
  public void readXmlDocument_xinclude() throws IOException {
    String xml = "<?xml version=\"1.0\"?>"
        + "<root xmlns=\"foo\" xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
        + "<xi:include href=\"file://" + tempFile + "\" parse=\"text\"/>"
        + "</root>";

    Document doc = XmlUtil.getInstance().readXmlDocument(new StringReader(xml));
    assertNotNull(doc);
    Element root = doc.getDocumentElement();
    assertEquals("", root.getTextContent());
  }
}
