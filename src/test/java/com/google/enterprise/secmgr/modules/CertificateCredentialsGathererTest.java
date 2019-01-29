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

package com.google.enterprise.secmgr.modules;

import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionState;
import com.google.enterprise.secmgr.authncontroller.CredentialsGathererElement;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.AuthnMechClient;
import com.google.enterprise.secmgr.config.AuthnMechNtlm;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.easymock.EasyMock;
import org.easymock.IMocksControl;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Tests Client Certificate Auth Credential gathering.
 *
 */
public class CertificateCredentialsGathererTest extends SecurityManagerTestCase {

  private AuthnMechanism clientMechanism;
  private AuthnMechanism otherMechanism;
  private SecurityManagerConfig config;
  private AuthnSession session;
  private CertificateCredentialsGatherer testGatherer;
  private static final String CERTIFICATE =
      "-----BEGIN CERTIFICATE-----\n" +
      "MIIC9TCCAl6gAwIBAgIJALQVfb0zIz6bMA0GCSqGSIb3DQEBBQUAMFsxCzAJBgNV\n" +
      "BAYTAlVTMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX\n" +
      "aWRnaXRzIFB0eSBMdGQxFDASBgNVBAMTC2V4YW1wbGUuY29tMB4XDTA5MDcxODA2\n" +
      "MjIyNloXDTEwMDcxODA2MjIyNlowWzELMAkGA1UEBhMCVVMxEzARBgNVBAgTClNv\n" +
      "bWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIG\n" +
      "A1UEAxMLZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKue\n" +
      "RG+YuGX6FifkJpYR+Gh/qF+PpGLSYVR7CzhGNh5a8RayKwPM8YNqsfKAT8VqLdAk\n" +
      "19x//cf03CgcUwLQsuUo3zxK4E110L96lVX6oF12FiIpSCVN+E93qin2W7VXw2Jt\n" +
      "fvQ4BllwdNMj/yNPl+bHuhtOjFAPpWEhCkSJP6NlAgMBAAGjgcAwgb0wHQYDVR0O\n" +
      "BBYEFD2DmpOW+OiFr6U3Nu7NuDGuBSJgMIGNBgNVHSMEgYUwgYKAFD2DmpOW+OiF\n" +
      "r6U3Nu7NuDGuBSJgoV+kXTBbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKU29tZS1T\n" +
      "dGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRQwEgYDVQQD\n" +
      "EwtleGFtcGxlLmNvbYIJALQVfb0zIz6bMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcN\n" +
      "AQEFBQADgYEAS7H+mB7lmEihX5lOWp9ZtyI7ua7MYVK05bbuBZJLAhO1mApu5Okg\n" +
      "DqcybVV8ijPLJkII75dn+q7olpwMmgyjjsozEKY1N0It9nRsb9fW2tKGp2qlCMA4\n" +
      "zP29U9091ZRH/xL1RPVzhkRHqfNJ/x+iTC4laSLBtwlsjjkd8Us6xrg=\n" +
      "-----END CERTIFICATE-----\n";

  @Override
  protected void setUp() throws Exception {
    super.setUp();

    // Set up testing AuthnSession.
    clientMechanism = AuthnMechClient.make("mech1");
    otherMechanism = AuthnMechNtlm.make("mech2", "http://sample.com");
    config
        = makeConfig(
            Lists.newArrayList(
                CredentialGroup.builder("group1", "group1 display", true, true, false)
                .addMechanism(clientMechanism)
                .build(),
                CredentialGroup.builder("group2", "group2 display", true, true, false)
                .addMechanism(otherMechanism)
                .build()));
    session = AuthnSession.newInstance(config);

    // Set up test clientAuth credential gatherer.
    testGatherer = ConfigSingleton.getInstance(CertificateCredentialsGatherer.class);
  }

  public void testWillHandle() {
    assertTrue(testGatherer.willHandle(session.getView(clientMechanism)));
    // Shouldn't handle other mechanism.
    assertFalse(testGatherer.willHandle(session.getView(otherMechanism)));
  }

  public void testStartGatheringSuccess() throws CertificateException {

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) factory.generateCertificate(
        new ByteArrayInputStream(CERTIFICATE.getBytes()));
    X509Certificate certs[] = {cert};
    request.setAttribute("javax.servlet.request.X509Certificate", certs);

    IMocksControl control = EasyMock.createControl();
    CredentialsGathererElement mockElement = control.createMock(CredentialsGathererElement.class);
    SessionView mockView = control.createMock(SessionView.class);
    AuthnAuthority mockAuthority = control.createMock(AuthnAuthority.class);
    CredentialGroup mockCredGroup = control.createMock(CredentialGroup.class);

    EasyMock.expect(mockView.getRequestId()).andReturn("MOCK_REQUEST_ID").anyTimes();
    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    EasyMock.expect(mockView.getCredentialGroup())
        .andReturn(mockCredGroup);
    EasyMock.expect(mockCredGroup.getName())
        .andReturn("group1");
    EasyMock.expect(mockView.getAuthority())
        .andReturn(mockAuthority);
    String message
        = "Got certificate DN CN=example.com,O=Internet Widgits Pty Ltd,ST=Some-State,C=US";
    EasyMock.expect(mockView.logMessage(message))
        .andReturn(message);
    mockElement.addSessionState(
        AuthnSessionState.of(mockAuthority,
            Verification.verified(
                1279434146000L,
                AuthnPrincipal.make(
                    "CN=example.com,O=Internet Widgits Pty Ltd,ST=Some-State,C=US", "group1"))));
    control.replay();

    assertFalse(testGatherer.startGathering(mockElement, request, response));
    control.verify();
  }

  public void testStartGatheringNoCert() {

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    IMocksControl control = EasyMock.createControl();
    CredentialsGathererElement mockElement = control.createMock(CredentialsGathererElement.class);
    SessionView mockView = control.createMock(SessionView.class);
    CredentialGroup mockCredGroup = control.createMock(CredentialGroup.class);
    EasyMock.expect(mockView.getRequestId()).andReturn("MOCK_REQUEST_ID").anyTimes();

    EasyMock.expect(mockElement.getSessionView())
        .andReturn(mockView);
    EasyMock.expect(mockView.getCredentialGroup())
        .andReturn(mockCredGroup);
    EasyMock.expect(mockCredGroup.getName())
        .andReturn("group1");
    String message = "No client certificate.";
    EasyMock.expect(mockView.logMessage(message))
        .andReturn(message);
    control.replay();

    assertFalse(testGatherer.startGathering(mockElement, request, response));
    control.verify();
  }
}
