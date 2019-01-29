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

package com.google.enterprise.secmgr.mock;

import static junit.framework.Assert.assertEquals;

import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import com.google.enterprise.secmgr.authzcontroller.Authorizer;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.saml.SecmgrCredential;
import com.google.enterprise.secmgr.servlets.SamlPdpBase;
import com.google.enterprise.secmgr.servlets.SamlPdpBase.DecodedRequest;
import com.google.enterprise.secmgr.servlets.SamlServlet;
import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.XMLHelper;

/**
 * A mock implementation of a SAML Policy Decision Point.
 */
public class MockSamlPdp extends SamlServlet implements PostableHttpServlet {
  private final SamlPdpBase pdp;
  private final Map<String, SecmgrCredential> goldenCredentialMap;

  public MockSamlPdp(SamlSharedData sharedData, Map<String, SecmgrCredential> goldenCredentialMap,
      AuthorizeWithCredential method, AuthnSessionManager authnSessionManager) {
    super(sharedData);
    pdp = SamlPdpBase.make(sharedData, new LocalAuthorizer(method), authnSessionManager);
    this.goldenCredentialMap = goldenCredentialMap;
  }

  @Override
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    initResponse(response);
    DecodedRequest decodedRequest = pdp.decodeAuthzRequest(request);
    SecmgrCredential expectedCred = goldenCredentialMap.get(decodedRequest.getSessionId());
    SecmgrCredential actualCred = decodedRequest.getCredential();

    try {
      // we have to compare the string representation here because we can not override
      // SecmgrCredentialImpl#equals method. The equals method is marked as final by its parent
      // class org.opensaml.common.impl.AbstractSAMLObject.
      String expectedCredStr = XMLHelper.prettyPrintXML(
          OpenSamlUtil.marshallXmlObject(expectedCred));
      String actualCredStr = XMLHelper.prettyPrintXML(
          OpenSamlUtil.marshallXmlObject(actualCred));
      assertEquals(expectedCredStr, actualCredStr);
    } catch (MarshallingException e) {
      throw new IOException(e);
    }

    pdp.authorize(request, response);
  }

  private final class LocalAuthorizer implements Authorizer {
    private final AuthorizeWithCredential method;

    public LocalAuthorizer(AuthorizeWithCredential method) {
      if (method == null) {
        throw new NullPointerException();
      }
      this.method = method;
    }

    @Override
    public AuthzResult apply(Collection<Resource> resources, String sessionId,
        boolean enableFastAuthz) {
      SecmgrCredential cred = goldenCredentialMap.get(sessionId);
      return method.authorize(resources, cred);
    }
  }
}
