// Copyright 2018 Google Inc.
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

import static com.google.enterprise.secmgr.testing.ServletTestUtil.generatePostContent;
import static com.google.enterprise.secmgr.testing.ServletTestUtil.makeMockHttpPost;

import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.AuthnMechBasic;
import com.google.enterprise.secmgr.config.AuthnMechForm;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.http.HttpExchange;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.mock.MockBasicAuthServer;
import com.google.enterprise.secmgr.mock.MockContentServer;
import com.google.enterprise.secmgr.mock.MockFormAuthServer;
import com.google.enterprise.secmgr.mock.MockIntegration;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * Unit tests for the DocumentFetcher (what documill uses).
 * 
 * See DocumentFetcherIntegrationTest for a tests covering the full pipeline.
 *
 */
public class DocumentFetcherTest extends SecurityManagerTestCase { 
  // private final DocumentFetcher fetcher;
  // private final MockHttpServletRequest mockRequest;
  // private final MockIntegration integration;
  // private final AuthnMechanism basicMech;
  // private final AuthnMechForm formMech;
  // private final SecurityManagerConfig config;
  // private final String basicSampleUrl;
  // private final String formSampleUrl;
  // private final GCookie formCookie;
  //
  // public DocumentFetcherTest() throws IOException, ServletException {
  //   this.integration = MockIntegration.make();
  //   this.fetcher = new DocumentFetcher(null, integration.getAuthnSessionManager());
  //   this.mockRequest = makeMockHttpPost(null, "http://localhost/");
  //
  //   MockBasicAuthServer server1 = new MockBasicAuthServer.Server1("http://gsa.google.com");
  //   this.integration.addMockServer(server1);
  //   this.basicSampleUrl = server1.getSampleUrl();
  //
  //   MockFormAuthServer server2 = new MockFormAuthServer.Form1("http://gsa2.google.com");
  //   this.integration.addMockServer(server2);
  //   this.formSampleUrl = server2.getSampleUrl();
  //   this.formCookie = server2.makeCookie(server2.getCookieName(),
  //       MockContentServer.COOKIE_VALUES.VALID.toString());
  //
  //   this.basicMech = AuthnMechBasic.make("basicMech", basicSampleUrl);
  //   this.formMech = AuthnMechForm.make("formMech", formSampleUrl);
  //   config = makeConfig(
  //       ImmutableList.of(
  //           CredentialGroup.builder(CredentialGroup.DEFAULT_NAME,
  //                                   CredentialGroup.DEFAULT_NAME,
  //                                   false, false ,false)
  //                          .addMechanism(basicMech)
  //                          .addMechanism(formMech)
  //                          .build()));
  // }
  //
  // @Override
  // public void setUp() throws Exception {
  //   super.setUp();
  //   integration.reset();
  //   ConfigSingleton.setConfig(config);
  // }
  //
  // public void testIsAllowed() {
  //   mockRequest.setRemoteAddr("127.0.0.1");
  //   assertTrue(fetcher.isAllowed(mockRequest));
  //
  //   mockRequest.setRemoteAddr("::1");
  //   assertTrue(fetcher.isAllowed(mockRequest));
  //
  //   mockRequest.setRemoteAddr("172.16.0.1");
  //   assertFalse(fetcher.isAllowed(mockRequest));
  //
  //   mockRequest.setRemoteAddr("2001:dead:beef::1");
  //   assertFalse(fetcher.isAllowed(mockRequest));
  // }
  //
  // public void testGetSession() throws IOException {
  //   AuthnSession returnedSession = fetcher.getSession(mockRequest);
  //   assertNotNull(returnedSession);
  //
  //   AuthnSession session = AuthnSession.newInstance();
  //   GCookie cookie = GCookie.make(SessionUtil.GSA_SESSION_ID_COOKIE_NAME, session.getSessionId());
  //   mockRequest.setCookies(new Cookie[] { cookie.toCookie() });
  //   mockRequest.addHeader(HttpUtil.HTTP_HEADER_COOKIE, cookie.requestHeaderString(true));
  //   generatePostContent(mockRequest);
  //
  //   returnedSession = fetcher.getSession(mockRequest);
  //   assertNotNull(returnedSession);
  //   assertEquals(session.getSessionId(), returnedSession.getSessionId());
  // }
  //
  // public void testDoBasicPost() {
  //   integration.setTestName();
  //   HttpExchange ex = integration.startDocumentFetch(this.basicSampleUrl);
  //   integration.assertStatusResult(HttpServletResponse.SC_UNAUTHORIZED, ex);
  //
  //   integration.getSession().addVerification(basicMech.getAuthority(),
  //       Verification.verified(Verification.NEVER_EXPIRES,
  //           AuthnPrincipal.make("joe", CredentialGroup.DEFAULT_NAME),
  //           CredPassword.make("plumber")));
  //
  //   ex = integration.startDocumentFetch(this.basicSampleUrl);
  //   integration.assertExchangeStatusOk(ex);
  //   integration.assertContentResult("You've won!!!", ex);
  // }
  //
  // public void testDoFormPost() {
  //   integration.setTestName();
  //   HttpExchange ex = integration.startDocumentFetch(this.formSampleUrl);
  //   integration.assertContentResult("Please login", ex);
  //
  //   integration.getSession().addCookie(formMech.getAuthority(), formCookie);
  //   ex = integration.startDocumentFetch(this.formSampleUrl);
  //   integration.assertExchangeStatusOk(ex);
  //   integration.assertContentResult("Welcome to the machine!", ex);
  // }
}
