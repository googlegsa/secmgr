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

import org.htmlcleaner.CommentNode;
import org.htmlcleaner.ContentNode;
import org.htmlcleaner.HtmlCleaner;
import org.htmlcleaner.TagNode;
import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import java.io.IOException;
import java.util.Map;

/**
 * An implementation of an HTML parser.  Designed to hide the details of the
 * parser behind the org.w3c DOM interface.
 */
public class HtmlParser {

  public static final String ATTR_ACTION = "action";
  public static final String ATTR_DISABLED = "disabled";
  public static final String ATTR_METHOD = "method";
  public static final String ATTR_NAME = "name";
  public static final String ATTR_TYPE = "type";
  public static final String ATTR_VALUE = "value";
  public static final String FORM_METHOD_POST = "POST";
  public static final String INPUT_TYPE_HIDDEN = "hidden";
  public static final String INPUT_TYPE_PASSWORD = "password";
  public static final String INPUT_TYPE_TEXT = "text";
  public static final String TAG_FORM = "form";
  public static final String TAG_INPUT = "input";

  // Don't instantiate this class.
  private HtmlParser() {}

  /**
   * Parse some HTML text given as a string.  Converts all HTML tag names and
   * attribute names to lower case.
   *
   * @param text The HTML text to parse.
   * @return A DOM tree for the parsed document.
   * @throws IOException
   */
  public static Document parse(String text) throws IOException {
    TagNode rootNode = (new HtmlCleaner()).clean(text);
    Document document = XmlUtil.getInstance()
        .makeDocument(null, rootNode.getName().toLowerCase(), null);
    convertTagNode(rootNode, document.getDocumentElement(), document);
    return document;
  }

  private static void convertTagNode(TagNode node, Element element, Document document) {
    Map<?, ?> attrsMap = node.getAttributes();
    for (Object key : attrsMap.keySet()) {
      String attrName = String.class.cast(key);
      element.setAttribute(attrName.toLowerCase(), String.class.cast(attrsMap.get(attrName)));
    }

    for (Object child : node.getAllChildren()) {
      if (child instanceof TagNode) {
        TagNode childNode = (TagNode) child;
        Element childElement = document.createElement(childNode.getName().toLowerCase());
        element.appendChild(childElement);
        convertTagNode(childNode, childElement, document);
      } else if (child instanceof ContentNode) {
        element.appendChild(convertContentNode((ContentNode) child, document));
      } else if (child instanceof CommentNode) {
        element.appendChild(convertCommentNode((CommentNode) child, document));
      }
    }
  }

  private static Text convertContentNode(ContentNode contentNode, Document document) {
    return document.createTextNode(contentNode.getContent());
  }

  private static Comment convertCommentNode(CommentNode commentNode, Document document) {
    return document.createComment(commentNode.getContent());
  }

  /**
   * Get the type of an HTML input element.
   *
   * @param input An HTML element (assumed to be an input element).
   * @return The type of the element in lower case, defaulted if necessary.
   */
  public static String getInputType(Element input) {
    String inputType = input.getAttribute(ATTR_TYPE);
    // Fill in default type if none specified.
    return (inputType == null || inputType.isEmpty()) ? INPUT_TYPE_TEXT : inputType.toLowerCase();
  }
}
