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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import com.google.enterprise.secmgr.authzcontroller.AuthorizationController;
import com.google.enterprise.secmgr.authzcontroller.AuthorizerImpl;
import com.google.enterprise.secmgr.common.AuthzMessages.AuthzRequest;
import com.google.enterprise.secmgr.common.AuthzMessages.AuthzResponse;
import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.ProtoBufferClient;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.mock.MockHttpTransport;
import com.google.enterprise.secmgr.mock.MockIntegration;
import com.google.enterprise.secmgr.mock.MockRelyingParty;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.modules.SamlAuthzClient;
import com.google.enterprise.secmgr.saml.Group;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.saml.SecmgrCredential;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import org.joda.time.DateTimeUtils;
import org.opensaml.messaging.handler.MessageHandlerException;

/**
 * Unit tests for {@link SamlAuthz}.
 */
public class SamlAuthzTest extends SecurityManagerTestCase {
  private static final Logger logger = Logger.getLogger(SamlAuthzTest.class.getName());
  private static final String USERNAME = "fred";

  private final AuthnSessionManager sessionManager;
  private final MockIntegration integration;
  private final SamlAuthzClient samlClient;
  private final AuthzServletTest.TestRunner testRunner;
  private final URI authzServletUri;
  private String sessionId;
  private Decorator decorator;

  public SamlAuthzTest()
      throws IOException, ServletException {
    sessionManager = ConfigSingleton.getInstance(AuthnSessionManager.class);
    integration = MockIntegration.make();
    samlClient
        = SamlAuthzClient.make(
            integration.getMetadata(),
            Metadata.getSmEntityId(),
            SamlSharedData.make(integration.getGsaEntityId(), SamlSharedData.Role.AUTHZ_CLIENT,
                null));
    testRunner = new LocalTestRunner();
    authzServletUri = URI.create(MockIntegration.getAuthzServletUrl(integration.getGsaHost()));
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();

    integration.reset();

    AuthnSession session = integration.makeSession();
    sessionId = session.getSessionId();
    decorator = SessionUtil.getLogDecorator(sessionId);
    AuthnMechanism mech = session.getMechanisms().get(0);
    session.addVerification(mech.getAuthority(),
        Verification.verified(
            Verification.NEVER_EXPIRES,
            AuthnPrincipal.make(USERNAME, session.getView(mech).getCredentialGroup().getName())));
  }

  private final class LocalTestRunner implements AuthzServletTest.TestRunner {
    final SamlSharedData sharedData
        = SamlSharedData.make(
            Metadata.getSmEntityId(),
            SamlSharedData.Role.AUTHZ_SERVER,
            null);

    @Override
    public void initServlet(AuthorizationController controller)
        throws ServletException, IOException {
      integration.getHttpTransport().registerServlet(
          MockIntegration.getSamlAuthzEndpoint(integration.getGsaHost()),
          SamlAuthz.getTestingInstance(sharedData,
              AuthorizerImpl.getTestingInstance(controller, sessionManager)));
    }

    @Override
    public void run(AuthzResult expected) throws IOException, MessageHandlerException {
      for (SamlAuthzClient.Protocol protocol : SamlAuthzClient.Protocol.values()) {
        SecmgrCredential cred = OpenSamlUtil.makeSecmgrCredential(sessionId, "", "", "",
            Collections.<Group>emptyList());
        AuthzResult actual
            = samlClient.sendAuthzRequest(protocol, expected.keySet(), cred, decorator, -1);
        assertEquals("Using protocol " + protocol, expected, actual);
      }
    }
  }

  public void testAllowAll() throws ServletException, IOException, MessageHandlerException {
    integration.setTestName();
    AuthzServletTest.runTestAllowAll(testRunner);
  }

  public void testAllowNone() throws ServletException, IOException, MessageHandlerException {
    integration.setTestName();
    AuthzServletTest.runTestAllowNone(testRunner);
  }

  public void testAlwaysIndeterminate()
      throws ServletException, IOException, MessageHandlerException {
    integration.setTestName();
    AuthzServletTest.runTestAlwaysIndeterminate(testRunner);
  }

  public void testAllowBySubstring() throws ServletException, IOException, MessageHandlerException {
    integration.setTestName();
    AuthzServletTest.runTestAllowBySubstring(testRunner);
  }

  public void testFastAuthzRequestTimes()
      throws IOException {
    integration.setTestName();

    Iterable<SamlAuthzClient.Protocol> protocolsToTest
        = ImmutableList.of(SamlAuthzClient.Protocol.BATCH_V2);
    //Iterable<SamlClient.Protocol> protocolsToTest = SamlClient.Protocol.values();
    Map<Object, List<Double>> results = Maps.newHashMap();

    MockHttpTransport.logMessages = false;
    try {
      for (SamlAuthzClient.Protocol protocol : protocolsToTest) {
        MockRelyingParty relyingParty = makeRelyingParty(protocol);
        getAuthzRequestTimes(relyingParty, WARM_UP_VECTOR);
        results.put(protocol, getAuthzRequestTimes(relyingParty, TEST_VECTOR));
      }
      ProtoBufferClient<AuthzRequest, AuthzResponse> client = AuthzServletTest.makeAuthzClient();
      getAuthzRequestTimes(client, WARM_UP_VECTOR);
      results.put("PROTO_BUFFER", getAuthzRequestTimes(client, TEST_VECTOR));
    } finally {
      MockHttpTransport.logMessages = true;
    }
    for (Map.Entry<Object, List<Double>> entry : results.entrySet()) {
      logger.info("Request times for protocol: " + entry.getKey());
      logAuthzRequestTimes(TEST_VECTOR, entry.getValue());
    }
  }

  private MockRelyingParty makeRelyingParty(SamlAuthzClient.Protocol protocol)
      throws IOException {
    return new MockRelyingParty(
        integration.getMetadata(),
        integration.getGsaEntityId(),
        Metadata.getSmEntityId(),
        protocol,
        // Use "fast" authz mode:
        true);
  }

  private static final TestVector WARM_UP_VECTOR
      = makeUrlTestVector(
          ImmutableList.of(100, 200),
          ImmutableList.of(1, 1));

  private static final TestVector TEST_VECTOR
      = makeUrlTestVector(
          ImmutableList.of(100, 200, 500, 1000, 2000, 5000),
          ImmutableList.of(10, 10, 10, 5, 2, 2));

  private static final class TestVector {
    List<Map.Entry<List<String>, Integer>> entries;

    TestVector(List<Map.Entry<List<String>, Integer>> entries) {
      this.entries = entries;
    }
  }

  private static TestVector makeUrlTestVector(List<Integer> lengths, List<Integer> repeats) {
    ImmutableList.Builder<Map.Entry<List<String>, Integer>> builder = ImmutableList.builder();
    for (int i = 0; i < lengths.size(); i += 1) {
      builder.add(Maps.immutableEntry(makeUrls(lengths.get(i)), repeats.get(i)));
    }
    return new TestVector(builder.build());
  }

  private static List<String> makeUrls(int n) {
    ImmutableList.Builder<String> builder = ImmutableList.builder();
    for (int i = 0; i < n; i += 1) {
      builder.add("http://example.com/test-" + n + "/" + i);
    }
    return builder.build();
  }

  private List<Double> getAuthzRequestTimes(MockRelyingParty relyingParty, TestVector testVector)
      throws IOException {
    ImmutableList.Builder<Double> builder = ImmutableList.builder();
    for (Map.Entry<List<String>, Integer> entry : testVector.entries) {
      List<String> urls = entry.getKey();
      int repeat = entry.getValue();
      for (int i = 0; i < repeat; i += 1) {
        builder.add(timeAuthzRequest(relyingParty, urls));
      }
    }
    return builder.build();
  }

  private List<Double> getAuthzRequestTimes(ProtoBufferClient<AuthzRequest, AuthzResponse> client,
      TestVector testVector)
      throws IOException {
    ImmutableList.Builder<Double> builder = ImmutableList.builder();
    for (Map.Entry<List<String>, Integer> entry : testVector.entries) {
      List<String> urls = entry.getKey();
      int repeat = entry.getValue();
      for (int i = 0; i < repeat; i += 1) {
        builder.add(timeAuthzRequest(client, urls));
      }
    }
    return builder.build();
  }

  private double timeAuthzRequest(MockRelyingParty relyingParty, List<String> urls)
      throws IOException {
    long startTime = DateTimeUtils.currentTimeMillis();
    relyingParty.authorize(urls, integration.getSessionId());
    return (DateTimeUtils.currentTimeMillis() - startTime) * 0.001;
  }

  private double timeAuthzRequest(ProtoBufferClient<AuthzRequest, AuthzResponse> client,
      List<String> identifiers)
      throws IOException {
    long startTime = DateTimeUtils.currentTimeMillis();
    AuthzServletTest.callAuthzServlet(
        client, authzServletUri, integration.getSessionId(), AuthzRequest.Mode.FAST, identifiers);
    return (DateTimeUtils.currentTimeMillis() - startTime) * 0.001;
  }

  private void logAuthzRequestTimes(TestVector testVector, List<Double> times) {
    List<Double> meanTimes = Lists.newArrayList();
    int t = 0;
    for (Map.Entry<List<String>, Integer> entry : testVector.entries) {
      int nUrls = entry.getKey().size();
      int repeatCount = entry.getValue();
      double totalTime = 0.0;
      for (int i = 0; i < repeatCount; i += 1) {
        double time = times.get(t++);
        totalTime += time;
        logger.info(String.format("Number of URLs: %d; time taken: %g", nUrls, time));
      }
      double meanTime = totalTime / repeatCount;
      meanTimes.add(meanTime);
    }
    List<Double> xs = Lists.newArrayList();
    List<Double> ys = Lists.newArrayList();
    for (int i = 0; i < testVector.entries.size(); i += 1) {
      int nUrls = testVector.entries.get(i).getKey().size();
      double meanTime = meanTimes.get(i);
      double urlsPerSec = nUrls / meanTime;
      logger.info(
          String.format("Number of URLs: %d; mean time: %g; mean URLs/sec: %g",
              nUrls, meanTime, urlsPerSec));
      xs.add((double) nUrls);
      ys.add(urlsPerSec);
    }
    logger.info("Theil-Sen slope: " + theilSenSlope(xs, ys));
  }

  /** http://en.wikipedia.org/wiki/Theil%E2%80%93Sen_estimator
   * This estimator is fairly insensitive to outliers. */
  private static double theilSenSlope(List<Double> xs, List<Double> ys) {
    List<Double> slopes = Lists.newArrayList();
    for (int i = 0; i < xs.size(); i += 1) {
      for (int j = 0; j < i; j += 1) {
        slopes.add((ys.get(i) - ys.get(j)) / (xs.get(i) - xs.get(j)));
      }
    }
    Collections.sort(slopes);
    int n = slopes.size() / 2;
    return ((slopes.size() % 2) == 1)
        ? slopes.get(n)
        : (slopes.get(n - 1) + slopes.get(n)) / 2.0;
  }
}
