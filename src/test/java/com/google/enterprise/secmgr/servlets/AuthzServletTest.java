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

import com.google.common.base.Supplier;
import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.authzcontroller.AuthorizationController;
import com.google.enterprise.secmgr.authzcontroller.AuthorizerImpl;
import com.google.enterprise.secmgr.common.AuthzMessages;
import com.google.enterprise.secmgr.common.AuthzMessages.AuthzRequest;
import com.google.enterprise.secmgr.common.AuthzMessages.AuthzResponse;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.ProtoBufferClient;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.http.HttpProtoBufferClient;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.mock.MockIntegration;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.protobuf.Message;
import java.io.IOException;
import java.net.URI;
import java.util.Collection;
import javax.servlet.ServletException;
import org.opensaml.xml.security.SecurityException;

/**
 * Unit tests for {@link AuthzServlet}.
 */
public class AuthzServletTest extends SecurityManagerTestCase {
  private static final String USERNAME = "fred";

  private final AuthnSessionManager sessionManager;
  private final MockIntegration integration;
  private final ProtoBufferClient<AuthzRequest, AuthzResponse> client;
  private final URI authzServletUri;
  private final TestRunner testRunner;
  private String sessionId;

  public AuthzServletTest()
      throws IOException, ServletException {
    sessionManager = ConfigSingleton.getInstance(AuthnSessionManager.class);
    integration = MockIntegration.make();
    client = makeAuthzClient();
    authzServletUri = URI.create(MockIntegration.getAuthzServletUrl(integration.getGsaHost()));
    testRunner = new LocalTestRunner();
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();

    integration.reset();

    AuthnSession session = integration.makeSession();
    sessionId = session.getSessionId();
    AuthnMechanism mech = session.getMechanisms().get(0);
    session.addVerification(mech.getAuthority(),
        Verification.verified(
            Verification.NEVER_EXPIRES,
            AuthnPrincipal.make(USERNAME, 
                session.getView(mech).getCredentialGroup().getName())));
  }

  interface TestRunner {
    public void initServlet(AuthorizationController controller)
        throws ServletException, IOException;
    public void run(AuthzResult expected)
        throws IOException, SecurityException;
  }

  private final class LocalTestRunner implements TestRunner {    
    @Override
    public void initServlet(AuthorizationController controller)
        throws ServletException {
      AuthzServlet authzServlet = AuthzServlet.getTestingInstance(
          AuthorizerImpl.getTestingInstance(controller, sessionManager));
      integration.getHttpTransport().registerServlet(
          MockIntegration.getAuthzServletUrl(integration.getGsaHost()), authzServlet);
    }

    @Override
    public void run(AuthzResult expected)
        throws IOException {
      AuthzResult actual
          = callAuthzServlet(client, authzServletUri, sessionId, AuthzRequest.Mode.ALL,
              expected.keySet());
      assertEquals(expected, actual);
    }
  }

  public void testgetResources()  {
    ImmutableList<Resource> resources = AuthzServlet.getResources(makeAuthzRequest(
        "user1", AuthzRequest.Mode.ALL, ImmutableList.<String>of("http://xyz.com")));
    assertEquals(AuthzStatus.PERMIT, resources.get(0).getPriorAclDecision());
  }
  
  public void testAllowAll()
      throws ServletException, IOException, SecurityException {
    integration.setTestName();
    runTestAllowAll(testRunner);
  }

  public void testAllowNone()
      throws ServletException, IOException, SecurityException {
    integration.setTestName();
    runTestAllowNone(testRunner);
  }

  public void testAlwaysIndeterminate()
      throws ServletException, IOException, SecurityException {
    integration.setTestName();
    runTestAlwaysIndeterminate(testRunner);
  }

  public void testAllowBySubstring()
      throws ServletException, IOException, SecurityException {
    integration.setTestName();
    runTestAllowBySubstring(testRunner);
  }

  static void runTestAllowAll(TestRunner runner)
      throws ServletException, IOException, SecurityException {
    runner.initServlet(ALLOW_ALL);
    runner.run(
        AuthzResult.of(
            "http://www.abc.com/secret.html", AuthzStatus.PERMIT,
            "http://xyz.com/fubar", AuthzStatus.PERMIT,
            "http://www.abc.com/notsecret.html", AuthzStatus.PERMIT));
  }

  static void runTestAllowNone(TestRunner runner)
      throws ServletException, IOException, SecurityException {
    runner.initServlet(ALLOW_NONE);
    runner.run(
        AuthzResult.of(
            "http://www.abc.com/secret.html", AuthzStatus.DENY,
            "http://xyz.com/fubar", AuthzStatus.DENY,
            "http://www.abc.com/notsecret.html", AuthzStatus.DENY));
  }

  static void runTestAlwaysIndeterminate(TestRunner runner)
      throws ServletException, IOException, SecurityException {
    runner.initServlet(ALWAYS_INDETERMINATE);
    runner.run(
        AuthzResult.of(
            "http://www.abc.com/secret.html", AuthzStatus.INDETERMINATE,
            "http://xyz.com/fubar", AuthzStatus.INDETERMINATE,
            "http://www.abc.com/notsecret.html", AuthzStatus.INDETERMINATE));
  }

  static void runTestAllowBySubstring(TestRunner runner)
      throws ServletException, IOException, SecurityException {
    runner.initServlet(ALLOW_BY_SUBSTRING);
    runner.run(
        AuthzResult.of(
            "http://www.abc.com/" + USERNAME + "/secret.html", AuthzStatus.PERMIT,
            "http://xyz.com/fubar", AuthzStatus.DENY,
            "http://www.abc.com/notsecretto" + USERNAME + ".html", AuthzStatus.PERMIT));
  }

  private static final AuthorizationController ALLOW_ALL =
    new AuthorizationController() {
      @Override
      public AuthzResult authorize(Collection<Resource> resources, SessionSnapshot snapshot,
           boolean enableFastAuthz) {
        AuthzResult.Builder builder = AuthzResult.builder(
            Resource.resourcesToUrls(resources));
        for (Resource resource : resources) {
          builder.put(resource.getUrl(), AuthzStatus.PERMIT);
        }
        return builder.build();
      }
    };

  private static final AuthorizationController ALLOW_NONE =
    new AuthorizationController() {
      @Override
      public AuthzResult authorize(Collection<Resource> resources, SessionSnapshot snapshot,
           boolean enableFastAuthz) {
        AuthzResult.Builder builder = AuthzResult.builder(
            Resource.resourcesToUrls(resources));
        for (Resource resource : resources) {
          builder.put(resource.getUrl(), AuthzStatus.DENY);
        }
        return builder.build();
      }
    };

  private static final AuthorizationController ALWAYS_INDETERMINATE =
    new AuthorizationController() {
      @Override
      public AuthzResult authorize(Collection<Resource> resources, SessionSnapshot snapshot,
           boolean enableFastAuthz) {
        AuthzResult.Builder builder = AuthzResult.builder(
            Resource.resourcesToUrls(resources));
        return builder.build();
      }
    };

  private static final AuthorizationController ALLOW_BY_SUBSTRING =
    new AuthorizationController() {
      @Override
      public AuthzResult authorize(Collection<Resource> resources, SessionSnapshot snapshot,
           boolean enableFastAuthz) {
        AuthzResult.Builder builder = AuthzResult.builder(
            Resource.resourcesToUrls(resources));
        for (Resource resource : resources) {
          builder.put(resource.getUrl(),
              resource.getUrl().contains(snapshot.getView().getUsername())
              ? AuthzStatus.PERMIT
              : AuthzStatus.DENY);
        }
        return builder.build();
      }
    };

  static ProtoBufferClient<AuthzRequest, AuthzResponse> makeAuthzClient() {
    return HttpProtoBufferClient.make(-1,
        new Supplier<Message.Builder>() {
          @Override
          public Message.Builder get() {
            return AuthzResponse.newBuilder();
          }
        },
        AuthzResponse.class);
  }

  static AuthzResult callAuthzServlet(ProtoBufferClient<AuthzRequest, AuthzResponse> client,
      URI authzServletUri, String subject, AuthzRequest.Mode mode, Iterable<String> identifiers)
      throws IOException {
    return decodeAuthzResponse(
        client.exchange(
            makeAuthzRequest(subject, mode, identifiers),
            authzServletUri));
  }

  private static AuthzRequest makeAuthzRequest(String subject, AuthzRequest.Mode mode,
      Iterable<String> identifiers) {    
    AuthzRequest.Builder builder = AuthzRequest.newBuilder();    
    builder.setSubject(subject);
    if (mode != AuthzRequest.Mode.ALL) {
      builder.setMode(mode);
    }
    for (String identifier : identifiers) {
      builder.addResource(
          AuthzRequest.Resource.newBuilder()
          .setIdentifier(identifier)
          .setEarlyDecision(AuthzMessages.AuthzStatus.PERMIT)
          .build());
    }
    return builder.build();
  }

  
  private static AuthzResult decodeAuthzResponse(AuthzResponse response) {
    AuthzResult.Builder builder = AuthzResult.builder();
    for (AuthzResponse.Resource resource : response.getResourceList()) {
      builder.put(resource.getIdentifier(),
          AuthzServlet.decodeDecision(resource.getDecision()));
    }
    return builder.build();
  }
}
