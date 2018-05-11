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

package com.google.enterprise.secmgr.modules;

import static com.google.enterprise.secmgr.common.XmlUtil.elementHasQname;
import static com.google.enterprise.secmgr.common.XmlUtil.findAttribute;
import static com.google.enterprise.secmgr.common.XmlUtil.findChildElement;
import static com.google.enterprise.secmgr.common.XmlUtil.getChildElementText;
import static com.google.enterprise.secmgr.common.XmlUtil.getChildElements;
import static com.google.enterprise.secmgr.common.XmlUtil.isElementWithQname;
import static com.google.enterprise.secmgr.common.XmlUtil.makeAttrChild;
import static com.google.enterprise.secmgr.common.XmlUtil.makeElementChild;
import static com.google.enterprise.secmgr.common.XmlUtil.makeTextElementChild;

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Multimap;
import com.google.common.collect.SetMultimap;
import com.google.common.collect.Sets;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnModule;
import com.google.enterprise.secmgr.authncontroller.AuthnModuleException;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.IdentityUtil;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.common.Stringify;
import com.google.enterprise.secmgr.common.XmlUtil;
import com.google.enterprise.secmgr.config.AuthnMechConnector;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.enterprise.secmgr.config.FlexAuthzRule.ParamName;
import com.google.enterprise.secmgr.http.ConnectorUtil;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.GroupMemberships;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.inject.Singleton;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A module that implements connector authentication.
 */
@Singleton
@ThreadSafe
public final class ConnectorModule implements AuthnModule, AuthzModule {
  private static final Logger logger = Logger.getLogger(ConnectorModule.class.getName());
  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());

  // Parenthesized group matches the connector-instance name.
  private static final Pattern URL_PATTERN = Pattern.compile("^googleconnector://([^./]*)");

  @Inject
  private ConnectorModule() {
    ConnectorUtil.initialize();
  }

  @Override
  public boolean willHandle(SessionView view) {
    return view.getMechanism() instanceof AuthnMechConnector;
  }

  // **************** authentication ****************

  /**
   * Send an authentication request to a connector manager, to see if the
   * username and password provided by a search user is valid for any of the
   * connectors the manager is responsible for.
   */
  @Override
  public AuthnSessionState authenticate(SessionView view)
      throws IOException, AuthnModuleException {
    AuthnMechConnector mech = AuthnMechConnector.class.cast(view.getMechanism());
    String connectorName = mech.getConnectorName();
    boolean doGroupLookupOnly = mech.doGroupLookupOnly();
    if (doGroupLookupOnly) {
      if (!view.hasVerifiedPrincipal()) {
        gsaLogger.info(view.getRequestId(), "Connector Auth failed; cannot lookup"
            + " groups without a verified user identity.");
        throw new AuthnModuleException("No verified principal while looking up groups.");
      }
    } else {
      if (!view.hasPrincipalAndPassword()) {
        gsaLogger.info(view.getRequestId(), "Connector Auth failed; missing principal"
            + " and/or password while authenticating user.");
        throw new AuthnModuleException("Missing principal and/or password while authenticating.");
      }
    }
    Document request = createAuthnRequest(view, connectorName, doGroupLookupOnly);
    String managerUrl = ConnectorUtil.getInstanceManagerUrl(connectorName);
    if (null == managerUrl) {
      managerUrl = ConnectorUtil.requireInstanceManagerUrl(connectorName);
    }
    Document response = ConnectorUtil.doExchange(request,
        managerUrl + ConnectorUtil.CM_AUTHENTICATE_SERVLET_PATH,
        mech.getTimeout());
    List<Element> responses = getAuthnResponses(response, view, connectorName, doGroupLookupOnly);
    Set<Credential> credentials = Sets.newHashSet();
    if (!doGroupLookupOnly) {
      credentials.addAll(view.getPrincipalAndPassword());
    }
    if (responses == null) {
      return AuthnSessionState.of(view.getAuthority(), Verification.refuted(credentials));
    }
    if (responses.isEmpty()) {
      return AuthnSessionState.empty();
    }
    Credential groups = localGroupLookup(responses, view);
    if (groups != null) {
      credentials.add(groups);
    }
    return AuthnSessionState.of(view.getAuthority(),
        Verification.verified(
            view.getConfiguredExpirationTime(),
            credentials));
  }

  private static Document createAuthnRequest(SessionView view, String connectorName,
      boolean doGroupLookupOnly) {
    Document document = XmlUtil.getInstance().makeDocument(ConnectorUtil.XML_TAG_AUTHN_REQUEST);
    Element root = document.getDocumentElement();
    if (!Strings.isNullOrEmpty(connectorName)) {
      Element connectors = makeElementChild(root, ConnectorUtil.XML_TAG_CONNECTORS);
      makeTextElementChild(connectors, ConnectorUtil.XML_TAG_CONNECTOR_NAME, connectorName);
    }
    Element credentials = makeElementChild(root, ConnectorUtil.XML_TAG_AUTHN_CREDENTIAL);
    makeTextElementChild(credentials, ConnectorUtil.XML_TAG_AUTHN_USERNAME, view.getUsername());
    String domain = view.getDomain();
    if (!Strings.isNullOrEmpty(domain)) {
      makeTextElementChild(credentials, ConnectorUtil.XML_TAG_AUTHN_DOMAIN, domain);
    }
    if (!doGroupLookupOnly) {
      makeTextElementChild(credentials, ConnectorUtil.XML_TAG_AUTHN_PASSWORD, view.getPassword());
    }
    return document;
  }

  private static List<Element> getAuthnResponses(Document document, SessionView view,
      String connectorName, boolean doGroupLookupOnly)
      throws AuthnModuleException {
    ImmutableList.Builder<Element> builder = ImmutableList.builder();
    Element root = document.getDocumentElement();
    String username = view.getUsername();
    AuthnController.check(isElementWithQname(root, ConnectorUtil.XML_TAG_RESPONSE_ROOT),
        "Authentication response not a <CmResponse> element");
    Element response = findChildElement(root, ConnectorUtil.XML_TAG_AUTHN_RESPONSE, false);
    AuthnController.check(response != null,
        "Authentication response missing <AuthnResponse> element");
    for (Element element : getChildElements(response)) {
      if (elementHasQname(element, ConnectorUtil.XML_TAG_FAILURE)) {
        checkConnectorName(element, connectorName);
        return null;
      }
      if (elementHasQname(element, ConnectorUtil.XML_TAG_SUCCESS)) {
        checkConnectorName(element, connectorName);
        String actual = getChildElementText(element, ConnectorUtil.XML_TAG_IDENTITY, false);
        if (actual == null) {
          // OK not to have username if doing only group lookup.
          AuthnController.check(doGroupLookupOnly,
              "Authentication response missing <Identity> element");
        } else {
          // Never OK to have wrong username.
          AuthnController.check(username.equals(actual),
              "Authentication response has wrong username: %s; should be %s",
              actual, username);
        }
        builder.add(element);
      }
    }
    List<Element> result = builder.build();
    AuthnController.check(!result.isEmpty(),
        "Authentication response contains no <Success> or <Failure> elements");
    return result;
  }

  private static void checkConnectorName(Element element, String connectorName)
      throws AuthnModuleException {
    String actual
        = findAttribute(element, ConnectorUtil.XML_ATTR_AUTHN_RESPONSE_CONNECTOR_NAME, false);
    AuthnController.check(connectorName.equals(actual),
        "Authentication response has incorrect connector name: %s",
        Stringify.object(actual));
  }

  private static GroupMemberships localGroupLookup(List<Element> responses, SessionView view) {
    ImmutableSet.Builder<Group> builder = ImmutableSet.builder();
    gsaLogger.info(view.getRequestId(), "Connector Auth: performing groups lookup.");
    for (Element response : responses) {
      for (Element groupElement : getChildElements(response, ConnectorUtil.XML_TAG_GROUP)) {
        Group group = makeGroup(groupElement, view);
        if (group != null) {
          builder.add(group);
        }
      }
    }
    ImmutableSet<Group> groupNames = builder.build();
    gsaLogger.info(view.getRequestId(), "Connector Auth: " + groupNames.size()
        + " groups found.");
    return groupNames.isEmpty() ? null : view.extendGroupMemberships(groupNames);
  }
  
  private static Group makeGroup(Element groupElement, SessionView view) {
    String groupName = XmlUtil.getElementText(groupElement);
    if (Strings.isNullOrEmpty(groupName)) {
      return null;
    }
    String namespace;
    try {
      namespace = findAttribute(groupElement, ConnectorUtil.XML_ATTR_NAMESPACE, true);
    } catch (IllegalArgumentException e) {
      gsaLogger.info(view.getRequestId(),
          "Connector Auth: namespace attribute not found for group " + groupName);
      return null;
    }
    if (!Strings.isNullOrEmpty(namespace)) {
      String principleType = findAttribute(groupElement,
          ConnectorUtil.XML_ATTR_PRINCIPAL_TYPE, false);
      if (ConnectorUtil.PRINCIPAL_TYPE_UNSPECIFIED.equals(principleType)){
        // this is a local group and does not need to be parsed out.
        return Group.make(groupName, namespace);
      }
      else {
        String[] tmpGroup = IdentityUtil.parseNameAndDomain(groupName);
        return Group.make(tmpGroup[0], namespace, tmpGroup[1]);
      }
    }
    return null;
  }

  // **************** authorization ****************

  @Override
  public AuthzResult authorize(Collection<Resource> resources, SessionView view,
      FlexAuthzRule rule) throws InterruptedIOException {
    Collection<String> urls = Resource.resourcesToUrls(resources);
    if (!view.isVerified()) {
      logger.info(view.logMessage("No verification for %s", view));
      return AuthzResult.makeIndeterminate(urls);
    }
    try {
      Collection<Document> documents =  SecurityManagerUtil.runInParallel(
          makeCallables(urls, view, rule),
          rule.hasTimeout() ? rule.getTimeout()
          : AuthnMechConnector.getDefaultTrustDuration() + 1000,
          view.getLogDecorator());
      return parseAuthzResponse(
          urls, documents);
    } catch (ExecutionException e) {
      logger.log(Level.WARNING, view.getLogDecorator().apply("Exception in worker thread: "),
          e.getCause());      
      if (e.getCause().getCause().getClass().equals(SocketTimeoutException.class)) {
        throw new InterruptedIOException(e.getMessage());
      }
    }
    return AuthzResult.makeIndeterminate(urls);
  }

  private List<Callable<Document>> makeCallables(Collection<String> urls, SessionView view,
      FlexAuthzRule rule) {
    Multimap<String, AuthzEntry> batches
        = splitByConnectorName(urls, rule.requiredStringParam(ParamName.CONNECTOR_NAME));
    ImmutableList.Builder<Callable<Document>> builder = ImmutableList.builder();
    for (String managerUrl : batches.keySet()) {
      builder.add(new LocalCallable(
          createAuthzRequest(batches.get(managerUrl), view),
          managerUrl + ConnectorUtil.CM_AUTHORIZATION_SERVLET_PATH,
          rule.hasTimeout() ? rule.getTimeout() : -1));
    }
    return builder.build();
  }

  private Multimap<String, AuthzEntry> splitByConnectorName(Collection<String> urls,
      String defaultConnectorName) {
    SetMultimap<String, AuthzEntry> batches = HashMultimap.create();
    for (String url : urls) {
      String connectorName = maybeOverrideConnectorName(url, defaultConnectorName);
      String managerUrl = ConnectorUtil.getInstanceManagerUrl(connectorName);
      if (managerUrl != null) {
        batches.put(managerUrl, new AuthzEntry(url, connectorName));
      }
    }
    return batches;
  }

  private static final class AuthzEntry {
    final String url;
    final String connectorName;

    AuthzEntry(String url, String connectorName) {
      this.url = url;
      this.connectorName = connectorName;
    }
  }

  // If this is a legacy connector URL, extract the connector from the URL.
  private static String maybeOverrideConnectorName(String url, String connectorName) {
    Matcher matcher = URL_PATTERN.matcher(url);
    if (matcher.find()) {
      return matcher.group(1);
    }
    return connectorName;
  }

  private static Document createAuthzRequest(Iterable<AuthzEntry> entries, SessionView view) {
    Document document = XmlUtil.getInstance().makeDocument(ConnectorUtil.XML_TAG_AUTHZ_QUERY);
    Element root = document.getDocumentElement();
    Element query = makeElementChild(root, ConnectorUtil.XML_TAG_CONNECTOR_QUERY);
    Element idElement
        = makeTextElementChild(query, ConnectorUtil.XML_TAG_IDENTITY, view.getUsername());
    String domain = view.getDomain();
    if (!Strings.isNullOrEmpty(domain)) {
      makeAttrChild(idElement, ConnectorUtil.XML_ATTR_DOMAIN, domain);
    }
    String password = view.getPassword();
    if (!Strings.isNullOrEmpty(password)) {
      makeAttrChild(idElement, ConnectorUtil.XML_ATTR_PASSWORD, password);
    }
    for (AuthzEntry entry : entries) {
      Element resource = makeTextElementChild(query, ConnectorUtil.XML_TAG_RESOURCE, entry.url);
      if (!Strings.isNullOrEmpty(entry.connectorName)) {
        makeAttrChild(resource, ConnectorUtil.XML_ATTR_CONNECTOR_NAME, entry.connectorName);
      }
    }
    return document;
  }

  private static AuthzResult parseAuthzResponse(Collection<String> urls,
      Collection<Document> documents) {

    AuthzResult.Builder builder = AuthzResult.builder(urls);
    for (Document document : documents) {
      Element root = document.getDocumentElement();
      Preconditions.checkArgument(isElementWithQname(root, ConnectorUtil.XML_TAG_RESPONSE_ROOT));
      Element response = findChildElement(root, ConnectorUtil.XML_TAG_AUTHZ_RESPONSE, false);
      if (response != null) {
        for (Element answer : getChildElements(response, ConnectorUtil.XML_TAG_ANSWER)) {
          String url = getChildElementText(answer, ConnectorUtil.XML_TAG_RESOURCE, true);
          String decisionText = getChildElementText(answer, ConnectorUtil.XML_TAG_DECISION, true);
          AuthzStatus decision;
          if (ConnectorUtil.DECISION_TEXT_PERMIT.equalsIgnoreCase(decisionText)) {
            decision = AuthzStatus.PERMIT;
          } else if (ConnectorUtil.DECISION_TEXT_DENY.equalsIgnoreCase(decisionText)) {
            decision = AuthzStatus.DENY;
          } else if (ConnectorUtil.DECISION_TEXT_INDETERMINATE.equalsIgnoreCase(decisionText)) {
            decision = AuthzStatus.INDETERMINATE;
          } else {
            throw new IllegalArgumentException("Unknown decision text: " + decisionText);
          }
          builder.put(url, decision);
        }
      }
    }
    return builder.build();
  }

  /**
   * The local implementation for the callable interface
   */
  private static final class LocalCallable implements Callable<Document> {
    private Document requestDocument;
    private String cmPath;
    private int timeout;

    public LocalCallable(Document requestDocument, String cmPath, int timeout) {
      this.requestDocument = requestDocument;
      this.cmPath = cmPath;
      this.timeout = timeout;
    }

    @Override
    public Document call()
        throws ExecutionException {
      try {
        return ConnectorUtil.doExchange(requestDocument, cmPath, timeout);
      } catch (IOException e) {
        throw new ExecutionException(e);
      }
    }
  }
}

