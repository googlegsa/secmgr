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

package com.google.enterprise.secmgr.servlets;

import com.google.common.collect.ImmutableSet;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.CredentialsGathererElement;
import com.google.enterprise.secmgr.authncontroller.ExportedState;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.IdentityUtil;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.common.Stringify;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.modules.SamlAuthnClient;
import com.google.enterprise.secmgr.modules.SamlCredentialsGatherer;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.util.HttpUtil;
import com.google.inject.Singleton;

import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.security.SecurityException;

import java.io.IOException;
import java.util.Set;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A servlet that implements the SAML "assertion consumer" role for SAML
 * credentials gathering.
 */
@Singleton
public class SamlAssertionConsumer extends SamlIdpServlet
    implements GettableHttpServlet, PostableHttpServlet {
  private static final Logger logger = Logger.getLogger(SamlAssertionConsumer.class.getName());
  private static final LogClient gsaLogger = new LogClient(
      "Security Manager", SecurityManagerUtil.getLogManagerServer());

  private static final DateTimeFormatter ISO8601_FORMAT = ISODateTimeFormat.dateTime();

  @Inject
  private SamlAssertionConsumer() {
    super(SamlSharedData.getProductionInstance(SamlSharedData.Role.SERVICE_PROVIDER));
  }

  @Override
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    handleRequest(request, response, SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    handleRequest(request, response, SAMLConstants.SAML2_POST_BINDING_URI);
  }

  private void handleRequest(HttpServletRequest request, HttpServletResponse response,
      String binding)
      throws IOException {
    AuthnSession session = AuthnSession.getInstance(request,
        /*createGsaSmSessionIfNotExist=*/false);
    if (session == null) {
      failNoSession(request, response);
      return;
    }
    session.updateIncomingCookies(request);
    try {
      CredentialsGathererElement element =
          session.getCredentialsGathererElement(SamlCredentialsGatherer.class);
      logger.info(session.logMessage("Received assertion via binding: " + binding));
      gsaLogger.info(
          session.getRequestId(), "Received incoming SAML assertion");
      gsaLogger.debug(session.getRequestId(),
          "Headers:\n" + HttpUtil.extractHeaderString(request));
      SamlAuthnClient client = element.getPrivateState(SamlAuthnClient.class);
      element.addSessionState(
          consumeAssertion(element,
              client.decodeResponse(request, binding),
              client.getAssertionConsumerService(binding).getLocation()));
      doAuthn(session, request, response);
    } catch (IOException e) {
      failFromException(e, session, request, response);
    } catch (SecurityException e) {
      failFromException(e, session, request, response);
    } catch (RuntimeException e) {
      if (SAMLConstants.SAML2_POST_BINDING_URI.equals(binding)) {
        failFromRuntimeExceptionWithPostBinding(e, session, request, response);
      } else {
        failFromException(e, session, request, response);
      }
    }
  }

  private AuthnSessionState consumeAssertion(CredentialsGathererElement element,
      Response samlResponse, String recipient) {
    SessionView view = element.getSessionView();
    SamlAuthnClient client = element.getPrivateState(SamlAuthnClient.class);
    if (samlResponse == null) {
      logger.warning(view.logMessage("SAML response is missing"));
      return AuthnSessionState.empty();
    }
    ResponseParser parser
        = ResponseParser.make(client, recipient, samlResponse, view.getSessionId());
    if (!parser.isResponseValid()) {
      logger.warning(view.logMessage("SAML response is invalid"));
      return AuthnSessionState.empty();
    }
    String code = parser.getResponseStatus();
    logger.info(view.logMessage("status code = %s", code));
    if (code.equals(StatusCode.SUCCESS_URI)) {

      if (!parser.areAssertionsValid()) {
        logger.warning(view.logMessage("One or more SAML assertions are invalid"));
        return AuthnSessionState.empty();
      }
      String subjectName = parser.getSubject();
      ImmutableSet.Builder<Credential> credentialsBuilder = ImmutableSet.builder();
      credentialsBuilder.add(AuthnPrincipal.parse(subjectName,
          view.getCredentialGroup().getName()));

      Set<Group> groups = parser.getGroupsFromExportedState();
      if (!groups.isEmpty()) {
        credentialsBuilder.add(view.extendGroupMemberships(groups));
      } else {
        ImmutableSet.Builder<Group> groupsBuilder = ImmutableSet.builder();
        String namespace = view.getCredentialGroup().getName();
        Set<String> groupsString = parser.getGroupsNoExportedState();
        for (String groupName : groupsString) {
          String[] tmpGroup = IdentityUtil.parseNameAndDomain(groupName);
          groupsBuilder.add(Group.make(tmpGroup[0], namespace, tmpGroup[1]));
        }
        Set<Group> finalGroups = groupsBuilder.build();
        if (!finalGroups.isEmpty()) {
          credentialsBuilder.add(view.extendGroupMemberships(finalGroups));
        }
      }
      DateTime expirationTime = parser.getExpirationTime();      
      logger.info(view.logMessage("SAML subject %s verified %s",
              Stringify.object(subjectName),
              ((expirationTime == null)
                  ? "forever"
                  : "until " + ISO8601_FORMAT.print(expirationTime))));
      AuthnSessionState state
          = AuthnSessionState.of(view.getAuthority(),
              Verification.verified(
                  view.getConfiguredExpirationTime(),
                  credentialsBuilder.build()));
      ExportedState exportedState = parser.getExportedState();
      if (exportedState != null) {
        state = state.add(exportedState.getSessionState());
      }
      return state;

    } else if (code.equals(StatusCode.AUTHN_FAILED_URI)) {
      return AuthnSessionState.of(view.getAuthority(), Verification.refuted());
    } else {
      logger.warning(view.logMessage("SAML IdP failed to resolve: %s", code));
      return AuthnSessionState.empty();
    }
  }
}
