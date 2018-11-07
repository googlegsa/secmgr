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
package com.google.enterprise.secmgr.servlets;

import static com.google.enterprise.secmgr.common.XmlUtil.getChildElements;

import com.google.common.annotations.VisibleForTesting;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import com.google.enterprise.secmgr.authncontroller.ExportedState;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.common.XmlUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.http.SlowHostTracker;
import com.google.enterprise.secmgr.modules.AuthzCacheModule;
import com.google.enterprise.secmgr.modules.PolicyAclsModule;
import com.google.inject.Singleton;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.logging.Logger;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

/**
 * Servlet to handle command sent to the security manager.
 * E.g., <Commands><ClearCache>true</ClearCache></Commands>
 *
 */
@Singleton
public class CommandsServlet extends HttpServlet {

  private static final Logger logger = Logger.getLogger(CommandsServlet.class.getName());
  public static final String CONFIG_XML_DECLARATION = "xml-declaration";
  public static final QName XML_TAG_SEC_MGR_COMMANDS = new QName("Commands");
  public static final QName XML_TAG_CLEAR_CACHE = new QName("ClearCache");
  public static final QName XML_TAG_SET_AUTHN_INFO = new QName("SetAuthNInfo");
  public static final QName XML_TAG_GET_AUTHN_INFO = new QName("GetAuthNInfo");
  public static final QName XML_TAG_SESSION_ID = new QName("SessionId");
  public static final String XML_SUCCESS = "SUCCESS";
  public static final QName XML_TAG_COMMAND_RESPONSE = new QName("CommandResponse");

  @Nullable private final AuthzCacheModule cacheModule;
  @Nullable private final PolicyAclsModule policyModule;
  @Nullable private final SlowHostTracker slowHostTracker;

  @Inject
  private CommandsServlet(AuthzCacheModule cacheModule, PolicyAclsModule policyModule,
                          SlowHostTracker slowHostTracker) {
    this.cacheModule = cacheModule;
    this.policyModule = policyModule;
    this.slowHostTracker = slowHostTracker;
  }

  @VisibleForTesting
  static CommandsServlet makeTestInstance() {
    return new CommandsServlet(null, null, null);
  }

  @Override
  // command for adminrunner to clear cache
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws IOException {
    logger.info("Clear cache");
    // enforce the request comes from the local host
    if (!isFromLocalhost(req)) {
      logger.warning("Request is not from localhost. Refused to serve.");
      return;
    }

    PrintWriter out;
    res.setContentType("text/xml");
    out = res.getWriter();
    clearCache(out);
    out.close();
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse res)
      throws IOException {

    // enforce the request comes from the local host
    if (!isFromLocalhost(req)) {
      logger.warning("Request is not from localhost. Refused to serve.");
      return;
    }

    PrintWriter out;
    res.setContentType("text/xml");
    out = res.getWriter();
    boolean emptyResponse = true;
    XmlUtil xmlUtil = XmlUtil.getInstance();
    Document reqDocument = xmlUtil.readXmlDocument(req.getReader());
    Element root = reqDocument.getDocumentElement();
    String sessionId = null;

    // get the session id element if it exists
    for (Element element : getChildElements(root)) {
      if (element.getTagName().equals(XML_TAG_SESSION_ID.getLocalPart())) {
        sessionId = element.getTextContent();
        break;
      }
    }

    // process the actual request: clear, setauthn, getauthn
    for (Element element : getChildElements(root)) {
      if (element.getTagName().equals(XML_TAG_CLEAR_CACHE.getLocalPart())) {
        // clear cache command
        if (Boolean.parseBoolean(element.getTextContent())) {
          clearCache(out);
          emptyResponse = false;
        }
      } else if (element.getTagName().equals(XML_TAG_SET_AUTHN_INFO.getLocalPart())) {
        // set the authn info from the xml request
        String authnJsonString = element.getTextContent();
        setAuthnInfo(sessionId, authnJsonString);
        emptyResponse = false;
      } else if (element.getTagName().equals(XML_TAG_GET_AUTHN_INFO.getLocalPart())) {
        // get the authn info
        String authnJsonString = getAuthnInfo(sessionId);
        out.println(authnJsonString);
        emptyResponse = false;
      }
    }

    if (emptyResponse) {
      writeXMLElement(out, XML_TAG_COMMAND_RESPONSE.getLocalPart(), "");
    }

    out.close();
  }

  public void clearCache(PrintWriter out) {
    logger.info("Clearing Security Manager Cache");
    if (cacheModule != null) {
      cacheModule.clearCache();
    }
    if (policyModule != null) {
      policyModule.reload();
    }
    if (slowHostTracker != null) {
      slowHostTracker.clearAllRecords();
    }
    writeXMLTag(out, XML_TAG_COMMAND_RESPONSE.getLocalPart(), false);
    writeXMLElement(out, XML_TAG_CLEAR_CACHE.getLocalPart(), XML_SUCCESS);
    writeXMLTag(out, XML_TAG_COMMAND_RESPONSE.getLocalPart(), true);
    return;
  }

  /** Write an XML tag to a PrintWriter
  *
  * @param out where PrintWriter to be written to
  * @param tagName String name of the XML tag to be added
  * @param endingTag String write a beginning tag if true or
  *        an ending tag if false
  */

  public static void writeXMLTag(PrintWriter out, String tagName, boolean endingTag) {
    out.println((endingTag ? "</" : "<") + (tagName) + ">");
  }

  /**
   * Write a name value pair as an XML element to a PrintWriter.
   *
   * @param out where PrintWriter to be written to
   * @param elemName element name
   * @param elemValue element value
   */

  public static void writeXMLElement(PrintWriter out, String elemName, String elemValue) {
    out.println("<" + elemName + ">" + elemValue + "</" + elemName + ">");
  }

  /**
   * check whether this HttpServletRequest comes from the localhost
   * @param req the request to be checked
   * @return true for localhost and false otherwise
   */
  private boolean isFromLocalhost(HttpServletRequest req) {
    boolean result = false;
    try {
      InetAddress addr = InetAddress.getByName(req.getRemoteAddr());
      result = addr.isLoopbackAddress();
    } catch (UnknownHostException e) {
      logger.warning("Unknown Host Exception.");
    }
    return result;
  }

  private String getAuthnInfo(String sessionId) {
    logger.info("GetAuthnInfo for " + sessionId);

    AuthnSessionManager authnsm = ConfigSingleton.getInstance(AuthnSessionManager.class);

    try {
      AuthnSession session = authnsm.findSessionById(sessionId);
      SessionSnapshot snapshot = session.getSnapshot();
      ExportedState state = ExportedState.make(snapshot);
      String jsonString = state.toJsonString();
      return jsonString;
    } catch (NullPointerException e) {
      logger.warning("Failed to get the session state of session id:" + sessionId);
      return "";
    }
  }

  private void setAuthnInfo(String sessionId, String authnInfo) {
    logger.info("SetAuthnInfo for " + sessionId);

    AuthnSessionManager authnsm = ConfigSingleton.getInstance(AuthnSessionManager.class);
    try {
      AuthnSession authnSession = authnsm.findSessionById(sessionId);
      authnSession.importSessionState(ExportedState.fromJsonString(authnInfo).getSessionState());
      authnsm.saveSession(authnSession);
    } catch (NullPointerException e) {
      logger.warning("Failed to import session state. NullPointerException:" + e);
    }
  }
}
