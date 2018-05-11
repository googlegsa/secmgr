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

package com.google.enterprise.secmgr.servlets;

import com.google.common.annotations.VisibleForTesting;
import com.google.enterprise.secmgr.authzcontroller.Authorizer;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.inject.Singleton;

import java.io.IOException;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A servlet that implements the SAML "policy decision point" service.  The GSA
 * sends messages here when using the security manager for authorization.
 */
@Singleton
public class SamlAuthz extends SamlServlet implements PostableHttpServlet {
  private final SamlPdpBase pdp;

  private SamlAuthz(SamlSharedData sharedData, Authorizer authorizer) {
    super(sharedData);
    pdp = SamlPdpBase.make(sharedData, authorizer);
  }

  @SuppressWarnings("unused")
  @Inject
  private SamlAuthz(Authorizer authorizer) {
    this(SamlSharedData.getProductionInstance(SamlSharedData.Role.AUTHZ_SERVER), authorizer);
  }

  @VisibleForTesting
  static SamlAuthz getTestingInstance(SamlSharedData sharedData, Authorizer authorizer) {
    return new SamlAuthz(sharedData, authorizer);
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    pdp.authorize(request, response);
  }
}
