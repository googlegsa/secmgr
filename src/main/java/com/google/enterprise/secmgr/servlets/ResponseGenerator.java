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

package com.google.enterprise.secmgr.servlets;

import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAttribute;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAttributeStatement;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAttributeValue;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAuthnStatement;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeSubject;

import com.google.enterprise.secmgr.authncontroller.ExportedState;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;

/**
 * This class is a mechanism for building a SAML Response message for the
 * successful outcome of an AuthnRequest message. It's done this way so that it
 * can be subclassed to tweak the response in a variety of ways.  The production
 * code uses a single type of response, but for testing we want to bend or break
 * the response so that we can test how the security manager's SAML client
 * interacts with partially broken IdPs.
 *
 * This is an abstract base class; there are several concrete classes used in a
 * variety of places.
 */
public abstract class ResponseGenerator {
  protected final DateTime now = new DateTime();

  /**
   * Generate a successful response from a session snapshot.
   */
  public Response generate(SessionSnapshot snapshot) {
    DateTime expirationTime = getExpirationTime(snapshot);
    Assertion assertion =
        buildAssertion(
            buildSubject(snapshot, expirationTime),
            buildConditions(expirationTime),
            makeAuthnStatement(now, AuthnContext.IP_PASSWORD_AUTHN_CTX),
            snapshot);
    AttributeStatement statement = buildAttributeStatement(snapshot);
    if (statement != null) {
      assertion.getAttributeStatements().add(statement);
    }
    return buildResponse(assertion);
  }

  protected abstract Response buildResponse(Assertion assertion);
  protected abstract Assertion buildAssertion(Subject subject, Conditions conditions,
      AuthnStatement statement, SessionSnapshot snapshot);
  protected abstract SubjectConfirmation buildSubjectConfirmation(DateTime expirationTime);
  protected abstract Conditions buildConditions(DateTime expirationTime);

  protected DateTime getExpirationTime(SessionSnapshot snapshot) {
    if (snapshot != null) {
      long expirationTime = snapshot.getExpirationTime();
      if (expirationTime > 0) {
        return new DateTime(expirationTime);
      }
    }
    // Expiration time is 30 seconds in the future.
    return now.plusMillis(30000);
  }

  protected Subject buildSubject(SessionSnapshot snapshot, DateTime expirationTime) {
    return makeSubject(
        buildSubjectName(snapshot),
        buildSubjectConfirmation(expirationTime));
  }

  protected String buildSubjectName(SessionSnapshot snapshot) {

    SessionView identity = snapshot.getPrimaryVerifiedView();
    if (identity != null) {
      String samlSubject = identity.getUsername();
      if (!samlSubject.isEmpty()) {
        return samlSubject;
      }
    }

    // Security safety valve: we must never return an empty verified identity,
    // or the GSA may share credentials between different users who appear to
    // have the same id.  As a samlSubject is transformed into a verified id,
    // create a useless random id rather than return a blank.
    return "unknown-subject-" + SecurityManagerUtil.generateRandomNonceHex(16);
  }

  protected AttributeStatement buildAttributeStatement(SessionSnapshot snapshot) {
    Attribute exportedStateAttribute = makeAttribute(ExportedState.ATTRIBUTE_NAME);
    exportedStateAttribute.getAttributeValues()
        .add(makeAttributeValue(ExportedState.make(snapshot).toJsonString()));
    Attribute sessionIdAttribute = makeAttribute("SessionId");
    sessionIdAttribute.getAttributeValues().add(makeAttributeValue(snapshot.getSessionId()));
    return makeAttributeStatement(exportedStateAttribute, sessionIdAttribute);
  }
}
