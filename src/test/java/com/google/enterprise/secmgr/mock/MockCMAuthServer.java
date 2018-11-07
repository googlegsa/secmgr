// Copyright 2008 Google Inc.
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

import static com.google.enterprise.secmgr.common.XmlUtil.elementHasQname;
import static com.google.enterprise.secmgr.common.XmlUtil.findAttribute;
import static com.google.enterprise.secmgr.common.XmlUtil.findChildElement;
import static com.google.enterprise.secmgr.common.XmlUtil.getChildElementText;
import static com.google.enterprise.secmgr.common.XmlUtil.getChildElements;
import static com.google.enterprise.secmgr.common.XmlUtil.getElementText;
import static com.google.enterprise.secmgr.common.XmlUtil.makeAttrChild;
import static com.google.enterprise.secmgr.common.XmlUtil.makeElementChild;
import static com.google.enterprise.secmgr.common.XmlUtil.makeTextElementChild;
import static com.google.enterprise.secmgr.http.ConnectorUtil.DECISION_TEXT_DENY;
import static com.google.enterprise.secmgr.http.ConnectorUtil.DECISION_TEXT_INDETERMINATE;
import static com.google.enterprise.secmgr.http.ConnectorUtil.DECISION_TEXT_PERMIT;
import static com.google.enterprise.secmgr.http.ConnectorUtil.ERROR_PARSING_XML_REQUEST;
import static com.google.enterprise.secmgr.http.ConnectorUtil.LOG_RESPONSE_EMPTY_NODE;
import static com.google.enterprise.secmgr.http.ConnectorUtil.PRINCIPAL_TYPE_UNSPECIFIED;
import static com.google.enterprise.secmgr.http.ConnectorUtil.RESPONSE_EMPTY_NODE;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_ATTR_AUTHN_RESPONSE_CONNECTOR_NAME;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_ATTR_CONNECTOR_NAME;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_ATTR_DOMAIN;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_ATTR_NAMESPACE;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_ATTR_PASSWORD;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_ATTR_PRINCIPAL_TYPE;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_ANSWER;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_AUTHN_CREDENTIAL;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_AUTHN_DOMAIN;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_AUTHN_PASSWORD;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_AUTHN_REQUEST;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_AUTHN_RESPONSE;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_AUTHN_USERNAME;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_AUTHZ_QUERY;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_AUTHZ_RESPONSE;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_CONNECTORS;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_CONNECTOR_NAME;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_CONNECTOR_QUERY;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_DECISION;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_FAILURE;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_GROUP;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_IDENTITY;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_RESOURCE;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_RESPONSE_ROOT;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_STATUS_ID;
import static com.google.enterprise.secmgr.http.ConnectorUtil.XML_TAG_SUCCESS;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.IdentityUtil;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.XmlUtil;
import com.google.enterprise.secmgr.http.ConnectorUtil;
import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A mock connector-manager authentication/authorization server.
 */
public final class MockCMAuthServer extends ServletBase
    implements PostableHttpServlet {
  private static final Logger LOGGER = Logger.getLogger(MockCMAuthServer.class.getName());
  public static final String DEFAULT_GROUPS_NS = "some namespace";
  public static final String LOCAL_GROUP_PREFIX = "local";

  /** "Function" interface for providing authorization.  */
  public interface Authorizer {
    public AuthzStatus apply(String url, String connectorName, String username, String domain,
        String password);
  }

  private final Set<String> allConnectorNames;
  private final Map<String, String> passwordMap;
  private final Map<String, Set<String> > groupsMap;
  private final XmlUtil xmlUtil;
  private Authorizer authorizer;
  private int authzCounter;

  public MockCMAuthServer() {
    allConnectorNames = Sets.newHashSet();
    passwordMap = Maps.newHashMap();
    groupsMap = Maps.newHashMap();
    xmlUtil = XmlUtil.getInstance();
    authzCounter = 0;
  }

  public void setPassword(String connectorName, String username, String domain, String password) {
    allConnectorNames.add(connectorName);
    String key = makePasswordKey(connectorName, domain, username);
    LOGGER.info("Registering password entry: " + key + " " + password);
    passwordMap.put(key, password);
  }


  public void addGroup(String connectorName, String username, String domain, String group) {
    allConnectorNames.add(connectorName);
    String key = makePasswordKey(connectorName, domain, username);
    LOGGER.info("Adding group info: " + key + " " + group);
    Set<String> groupSet = groupsMap.get(key);
    if (groupSet == null) {
      groupSet = Sets.newHashSet();
    }
    groupSet.add(group);
    groupsMap.put(key, groupSet);
  }

  public void setAuthorizer(Authorizer authorizer) {
    this.authorizer = authorizer;
  }

  public int getAuthzCounter() {
    return authzCounter;
  }

  public void resetAuthzCounter() {
    authzCounter = 0;
  }

  @Override
  public void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws IOException {
    Element root = xmlUtil.readXmlDocument(req.getReader()).getDocumentElement();
    Document response;
    if (root == null) {
      response = makeStatusResponse(ERROR_PARSING_XML_REQUEST);
    } else if (elementHasQname(root, XML_TAG_AUTHN_REQUEST)) {
      response = handleAuthnRequest(root);
    } else if (elementHasQname(root, XML_TAG_AUTHZ_QUERY)) {
      response = handleAuthzRequest(root);
    } else {
      response = makeStatusResponse(ERROR_PARSING_XML_REQUEST);
    }
    xmlUtil.writeXmlDocument(response, resp.getWriter());
  }

  // **************** authentication ****************

  private Document handleAuthnRequest(Element root) {
    Element credential = findChildElement(root, XML_TAG_AUTHN_CREDENTIAL, false);
    if (credential == null) {
      LOGGER.warning(LOG_RESPONSE_EMPTY_NODE);
      return makeStatusResponse(RESPONSE_EMPTY_NODE);
    }

    String username = getChildElementText(credential, XML_TAG_AUTHN_USERNAME, true);
    String domain = getChildElementText(credential, XML_TAG_AUTHN_DOMAIN, false);
    String password = getChildElementText(credential, XML_TAG_AUTHN_PASSWORD, false);
    Set<String> connectorNames = parseConnectorNames(root);

    Document responseDoc = xmlUtil.makeDocument(XML_TAG_RESPONSE_ROOT);
    Element response = responseDoc.getDocumentElement();
    Element authnResponse = makeElementChild(response, XML_TAG_AUTHN_RESPONSE);

    for (String connectorName : connectorNames) {
      String key = makePasswordKey(connectorName, domain, username);
      String expectedPassword = passwordMap.get(key);
      Set<String> groups = groupsMap.get(key);
      LOGGER.info("Authenticate " + key + ": expecting " + expectedPassword + " got " + password);
      LOGGER.info("Group info of " + key + ": " + groups);
      Element status;
      if (password == null || password.equals(expectedPassword)) {
        status = makeElementChild(authnResponse, XML_TAG_SUCCESS);
        if (password != null) {
          Element groupElement = makeTextElementChild(status, XML_TAG_IDENTITY, username);
        }
        if (groups != null) {
          for (String group : groups) {
            Element groupElement = makeTextElementChild(status, XML_TAG_GROUP, group);
            makeAttrChild(groupElement, XML_ATTR_NAMESPACE, DEFAULT_GROUPS_NS);
            if (group.startsWith(LOCAL_GROUP_PREFIX)) {
              makeAttrChild(groupElement, XML_ATTR_PRINCIPAL_TYPE, PRINCIPAL_TYPE_UNSPECIFIED);
            }
          }
        }
      } else {
        status = makeElementChild(authnResponse, XML_TAG_FAILURE);
      }
      makeAttrChild(status, XML_ATTR_AUTHN_RESPONSE_CONNECTOR_NAME, connectorName);
    }

    return responseDoc;
  }

  private Document makeStatusResponse(int statusId) {
    Document responseDoc = xmlUtil.makeDocument(XML_TAG_RESPONSE_ROOT);
    makeTextElementChild(
        responseDoc.getDocumentElement(),
        XML_TAG_STATUS_ID,
        Integer.toString(statusId));
    return responseDoc;
  }

  private Set<String> parseConnectorNames(Element root) {
    Element connectors = findChildElement(root, XML_TAG_CONNECTORS, false);
    if (connectors == null) {
      return allConnectorNames;
    }
    ImmutableSet.Builder<String> builder = ImmutableSet.builder();
    for (Element child : getChildElements(connectors, XML_TAG_CONNECTOR_NAME)) {
      builder.add(getElementText(child));
    }
    return builder.build();
  }

  private static String makePasswordKey(String connectorName, String domain, String username) {
    return connectorName + ":" + IdentityUtil.joinNameDomain(username, domain);
  }

  // **************** authorization ****************

  private Document handleAuthzRequest(Element authzRequest) {
    authzCounter += 1;
    Preconditions.checkArgument(elementHasQname(authzRequest, XML_TAG_AUTHZ_QUERY));
    Element query = findChildElement(authzRequest, XML_TAG_CONNECTOR_QUERY, true);
    Element idElement = findChildElement(query, XML_TAG_IDENTITY, true);
    String username = getElementText(idElement);
    String domain = findAttribute(idElement, XML_ATTR_DOMAIN, false);
    String password = findAttribute(idElement, XML_ATTR_PASSWORD, false);
    Document responseDoc = xmlUtil.makeDocument(XML_TAG_RESPONSE_ROOT);
    Element root = responseDoc.getDocumentElement();
    Element response = makeElementChild(root, XML_TAG_AUTHZ_RESPONSE);
    for (Element resource : getChildElements(query, XML_TAG_RESOURCE)) {
      String url = getElementText(resource);
      String connectorName = findAttribute(resource, XML_ATTR_CONNECTOR_NAME, false);
      String decisionText = getDecision(url, connectorName, username, domain, password);
      Element answer = makeElementChild(response, XML_TAG_ANSWER);
      makeResourceChild(answer, url, connectorName);
      makeTextElementChild(answer, XML_TAG_DECISION, decisionText);
    }
    return responseDoc;
  }

  private String getDecision(String url, String connectorName, String username, String domain,
      String password) {
    switch (authorizer.apply(url, connectorName, username, domain, password)) {
      case PERMIT: return DECISION_TEXT_PERMIT;
      case DENY: return DECISION_TEXT_DENY;
      default: return DECISION_TEXT_INDETERMINATE;
    }
  }

  private void makeResourceChild(Element parent, String url, String connectorName) {
    Element resource = makeTextElementChild(parent, ConnectorUtil.XML_TAG_RESOURCE, url);
    if (!Strings.isNullOrEmpty(connectorName)) {
      makeAttrChild(resource, ConnectorUtil.XML_ATTR_CONNECTOR_NAME, connectorName);
    }
  }
}
