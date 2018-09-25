// Copyright 2010 Google Inc.
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

import static com.google.enterprise.secmgr.common.XmlUtil.makeElementChild;
import static com.google.enterprise.secmgr.common.XmlUtil.makeTextElementChild;
import static com.google.enterprise.secmgr.http.ConnectorUtil.RESPONSE_NULL_CONNECTOR;
import static com.google.enterprise.secmgr.http.ConnectorUtil.SUCCESS;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_CONNECTOR_INSTANCE;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_CONNECTOR_INSTANCES;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_CONNECTOR_NAME;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_INFO;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_RESPONSE_ROOT;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_STATUS_ID;

import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.XmlUtil;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A mock connector-manager instance-list server.
 */
public final class MockGetConnectorInstanceList
    extends HttpServlet
    implements PostableHttpServlet {

  private final ImmutableList<String> connectorNames;
  private final XmlUtil xmlUtil;

  public MockGetConnectorInstanceList(Iterable<String> connectorNames) {
    this.connectorNames = ImmutableList.copyOf(connectorNames);
    xmlUtil = XmlUtil.getInstance();
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    PrintWriter writer = response.getWriter();
    try {
      xmlUtil.writeXmlDocument(makeResponseDocument(), writer);
    } finally {
      writer.close();
    }
  }

  private Document makeResponseDocument() {
    Document document = xmlUtil.makeDocument(XML_TAG_RESPONSE_ROOT);
    Element root = document.getDocumentElement();
    makeTextElementChild(root, XML_TAG_INFO, "Mock Connector Manager");
    if (connectorNames.isEmpty()) {
      makeTextElementChild(root, XML_TAG_STATUS_ID, Integer.toString(RESPONSE_NULL_CONNECTOR));
    } else {
      makeTextElementChild(root, XML_TAG_STATUS_ID, Integer.toString(SUCCESS));
      Element instances = makeElementChild(root, XML_TAG_CONNECTOR_INSTANCES);
      for (String connectorName : connectorNames) {
        Element instance = makeElementChild(instances, XML_TAG_CONNECTOR_INSTANCE);
        makeTextElementChild(instance, XML_TAG_CONNECTOR_NAME, connectorName);
      }
    }
    return document;
  }
}
