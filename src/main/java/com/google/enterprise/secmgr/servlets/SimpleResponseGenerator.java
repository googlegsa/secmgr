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

import static com.google.enterprise.secmgr.saml.OpenSamlUtil.BEARER_METHOD;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAssertion;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeAudienceRestriction;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeConditions;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeResponse;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeSubjectConfirmation;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeSubjectConfirmationData;
import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeSuccessfulStatus;

import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;

import org.joda.time.DateTime;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;

/**
 * This is an implementation of a response generator in which contextual
 * information is explicitly supplied during instantiation.  This class builds a
 * fully-compliant SAML response.
 */
public class SimpleResponseGenerator extends ResponseGenerator {

  protected final String recipient;
  protected final String audience;
  protected final String inResponseTo;
  protected final String issuer;

  /**
   * Make a new ResponseGenerator instance.  Accepts the contextual information
   * as an OpenSAML message context.
   *
   * @param context A properly-initialize OpenSAML message context.
   */
  public SimpleResponseGenerator(SAMLMessageContext<AuthnRequest, Response, NameID> context) {
    this(context.getPeerEntityEndpoint().getLocation(),
        context.getInboundMessageIssuer(),
        context.getInboundSAMLMessage().getID(),
        context.getLocalEntityId());
  }

  /**
   * Make a new ResponseGenerator instance.  Accepts the contextual information
   * as individual items.
   *
   * @param recipient A URL identifying the endpoint that the response will be sent to.
   * @param audience The entity ID of the service provider the response is intended for.
   * @param inResponseTo The message ID of the AuthnRequest this is a response to.
   * @param issuer The entity ID of the identity provider sending this response.
   */
  public SimpleResponseGenerator(String recipient, String audience, String inResponseTo,
      String issuer) {
    this.recipient = recipient;
    this.audience = audience;
    this.inResponseTo = inResponseTo;
    this.issuer = issuer;
  }

  @Override
  protected Response buildResponse(Assertion assertion) {
    return makeResponse(issuer, now, makeSuccessfulStatus(), inResponseTo, assertion);
  }

  @Override
  protected Assertion buildAssertion(Subject subject, Conditions conditions,
      AuthnStatement statement, SessionSnapshot snapshot) {
    return makeAssertion(issuer, now, subject, conditions, statement);
  }

  @Override
  protected SubjectConfirmation buildSubjectConfirmation(DateTime expirationTime) {
    return makeSubjectConfirmation(BEARER_METHOD,
        makeSubjectConfirmationData(recipient, expirationTime, inResponseTo));
  }

  @Override
  protected Conditions buildConditions(DateTime expirationTime) {
    return makeConditions(now, expirationTime, makeAudienceRestriction(audience));
  }
}
