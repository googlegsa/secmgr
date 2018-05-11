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

import static com.google.enterprise.secmgr.saml.OpenSamlUtil.makeResponse;

import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;

import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;

/**
 * This is an implementation of a response generator for unsuccessful responses.
 */
public class FailureResponseGenerator extends SimpleResponseGenerator {

  private final Status status;

  public FailureResponseGenerator(SAMLMessageContext<AuthnRequest, Response, NameID> context,
      Status status) {
    super(context);
    this.status = status;
  }

  @Override
  public Response generate(SessionSnapshot snapshot) {
    return buildResponse(null);
  }

  @Override
  protected Response buildResponse(Assertion assertion) {
    return makeResponse(issuer, now, status, inResponseTo);
  }
}
