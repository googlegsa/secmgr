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

package com.google.enterprise.secmgr.common;

import java.io.IOException;
import java.util.logging.Logger;
import junit.framework.TestCase;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

/**
 * Tests for the {@link HtmlParser} class.
 */
public class HtmlParserTest extends TestCase {
  private static final Logger logger = Logger.getLogger(HtmlParserTest.class.getName());

  private static final String SIMPLE_PAGE_TEXT = "Trivial page";
  private static final String SIMPLE_PAGE = "<html><body>" + SIMPLE_PAGE_TEXT + "</body></html>";

  private static final String FORM_PAGE_ACTION = "submit-form-here.html";
  private static final String FORM_PAGE =
      "<html><body>\n" +
      "Please login:\n" +
      "<form action=\"" + FORM_PAGE_ACTION + "\">" +
      "<input type=\"text\" name=\"username\" />" +
      "<input type=\"password\" name=\"password\" />" +
      "</form></body></html>\n";
  private static final String FORM_PAGE_UPPER_CASE =
      "<HTML><BODY>\n" +
      "Please login:\n" +
      "<FORM ACTION=\"" + FORM_PAGE_ACTION + "\">" +
      "<INPUT TYPE=\"TEXT\" NAME=\"username\" />" +
      "<INPUT TYPE=\"PASSWORD\" NAME=\"password\" />" +
      "</FORM></BODY></HTML>\n";

  public void testSimplePage() {
    Document document = callParser(SIMPLE_PAGE);
    Element root = document.getDocumentElement();
    expectElement("html", 0, 2, root);
    expectElement("head", 0, 0, getChild(root, 0));
    expectElement("body", 0, 1, getChild(root, 1));
    Node body = getChild(getChild(root, 1), 0);
    assertTrue(body instanceof Text);
    assertEquals(SIMPLE_PAGE_TEXT, body.getNodeValue());
  }

  public void testFormPage() {
    tryFormPage(FORM_PAGE);
  }

  public void testFormPageUpperCase() {
    tryFormPage(FORM_PAGE_UPPER_CASE);
  }

  public void tryFormPage(String text) {
    Document document = callParser(text);
    NodeList forms = document.getElementsByTagName("form");
    assertEquals(1, forms.getLength());
    Node form = forms.item(0);
    expectElement("form", 1, 2, form);
    assertAttributeWithName("action", getAttribute(form, 0));
    assertEquals(FORM_PAGE_ACTION, getAttribute(form, 0).getNodeValue());
    expectInput("text", "username", getChild(form, 0));
    expectInput("password", "password", getChild(form, 1));
  }

  private Document callParser(String text) {
    try {
      return HtmlParser.parse(text);
    } catch (IOException e) {
      fail("IOException while parsing: " + e);
      return null;
    }
  }

  private Node getChild(Node node, int index) {
    return node.getChildNodes().item(index);
  }

  private Node getAttribute(Node node, int index) {
    return node.getAttributes().item(index);
  }

  private void expectElement(String tagName, int nAttrs, int nChildren, Node node) {
    assertElementWithTag(tagName, node);
    assertEquals(nAttrs, node.getAttributes().getLength());
    logChildren(node);
    assertEquals(nChildren, node.getChildNodes().getLength());
  }

  private void expectInput(String type, String name, Node node) {
    expectElement("input", 2, 0, node);
    assertEquals(type, HtmlParser.getInputType((Element) node));
    assertTrue(name.equalsIgnoreCase(((Element) node).getAttribute("name")));
  }

  private void assertElementWithTag(String tagName, Node node) {
    assertTrue(node instanceof Element);
    assertEquals(tagName, node.getNodeName());
    assertNotNull(node.getAttributes());
  }

  private void assertAttributeWithName(String name, Node node) {
    assertTrue(node instanceof Attr);
    assertEquals(name, node.getNodeName());
  }

  private void logChildren(Node node) {
    NodeList children = node.getChildNodes();
    logger.info("Number of children: " + children.getLength());
    for (int i = 0; i < children.getLength(); i++) {
      Node child = children.item(i);
      logger.info("Child #" + i + ": name=\"" + child.getNodeName() + "\"");
    }
  }
}
