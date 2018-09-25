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

package com.google.enterprise.secmgr.ntlmssp;

import static com.google.enterprise.secmgr.common.SecurityManagerUtil.bytesToHex;
import static com.google.enterprise.secmgr.common.SecurityManagerUtil.hexToBytes;

import com.google.common.base.Function;
import com.google.common.collect.Maps;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Map;
import junit.framework.TestCase;

/**
 * Unit tests for {@link NtlmV1Client}.
 */
public final class NtlmV1ClientTest extends TestCase {
  private static final String DOMAIN_NAME = "MYDOMAIN.COM";
  private static final String BAD_DOMAIN_NAME = "NODOMAIN.COM";
  private static final String USER_NAME = "mememe";
  private static final String UNKNOWN_USER_NAME = "youyouyou";
  private static final String PASSWORD = "mineminemine";
  private static final String BAD_PASSWORD = "yoursyoursyours";
  private static final String WORKSTATION_NAME = "MYWORKSTATION";
  private static final String SERVER_WORKSTATION_NAME = "YOURWORKSTATION";

  private static final String FIXED_DOMAIN_NAME = "ES-TEST-DOM1";
  private static final String FIXED_USER_NAME = "user1";
  private static final String FIXED_PASSWORD = "test1";
  private static final String FIXED_WORKSTATION_NAME = "omerie";
  private static final String FIXED_SERVER_CHALLENGE = "8b46eb0ee51fcc7b";
  private static final String FIXED_CLIENT_CHALLENGE = "2c1477c5ca4565c9";
  private static final String FIXED_RESPONSE = "7e9d938f6043c8656b497b097be93f6e1d99460dc0a5c574";

  /**
   * Test connection to domain controller from a workstation that's not in the domain.
   */
  public void testGoodNoDomain()
      throws GeneralSecurityException, UnsupportedEncodingException {
    NtlmV1Client client = NtlmV1Client.builder()
        .setUserName(USER_NAME)
        .setPassword(PASSWORD)
        .setWorkstationName(WORKSTATION_NAME)
        .build();
    assertTrue(runDomainExchange(client));
  }

  /**
   * Test connection to domain controller from a member of the same domain.
   */
  public void testGoodDomain()
      throws GeneralSecurityException, UnsupportedEncodingException {
    NtlmV1Client client = NtlmV1Client.builder()
        .setDomainName(DOMAIN_NAME)
        .setUserName(USER_NAME)
        .setPassword(PASSWORD)
        .build();
    assertTrue(runDomainExchange(client));
  }

  /**
   * Test connection to domain controller from a member of another domain.
   */
  public void testBadDomain()
      throws GeneralSecurityException, UnsupportedEncodingException {
    NtlmV1Client client = NtlmV1Client.builder()
        .setDomainName(BAD_DOMAIN_NAME)
        .setUserName(USER_NAME)
        .setPassword(PASSWORD)
        .build();
    assertFalse(runDomainExchange(client));
  }

  /**
   * Test login with unknown user name.
   */
  public void testUnknownUser()
      throws GeneralSecurityException, UnsupportedEncodingException {
    NtlmV1Client client = NtlmV1Client.builder()
        .setUserName(UNKNOWN_USER_NAME)
        .setPassword(PASSWORD)
        .setWorkstationName(WORKSTATION_NAME)
        .build();
    assertFalse(runDomainExchange(client));
  }

  /**
   * Test login with wrong password.
   */
  public void testBadPassword()
      throws GeneralSecurityException, UnsupportedEncodingException {
    NtlmV1Client client = NtlmV1Client.builder()
        .setUserName(USER_NAME)
        .setPassword(BAD_PASSWORD)
        .setWorkstationName(WORKSTATION_NAME)
        .build();
    assertFalse(runDomainExchange(client));
  }

  /**
   * Run standard exchange to domain controller.
   */
  private boolean runDomainExchange(NtlmV1Client client)
      throws GeneralSecurityException, UnsupportedEncodingException {
    return finishExchange(client,
        NtlmV1Server.builder()
        .setDomainName(DOMAIN_NAME)
        .setLookupPassword(makePasswordDb(DOMAIN_NAME, USER_NAME, PASSWORD))
        .setNegotiateMessage(client.createNegotiateMessage())
        .build());
  }

  /**
   * Test connecting from one workstation to another without domain controller.
   */
  public void testGoodWorkstation()
      throws GeneralSecurityException, UnsupportedEncodingException {
    NtlmV1Client client = NtlmV1Client.builder()
        .setUserName(USER_NAME)
        .setPassword(PASSWORD)
        .setWorkstationName(WORKSTATION_NAME)
        .build();
    assertTrue(runWorkstationExchange(client));
  }

  /**
   * Run standard exchange to non-domain workstation.
   */
  private boolean runWorkstationExchange(NtlmV1Client client)
      throws GeneralSecurityException, UnsupportedEncodingException {
    return finishExchange(client,
        NtlmV1Server.builder()
        .setWorkstationName(SERVER_WORKSTATION_NAME)
        .setLookupPassword(makePasswordDb(null, USER_NAME, PASSWORD))
        .setNegotiateMessage(client.createNegotiateMessage())
        .build());
  }

  /**
   * Test a known-good exchange.  This simulates a successful exchange that was
   * recorded between Firefox and IIS.  It checks that the crypto is properly
   * set up for IIS interaction.
   */
  public void testFixedExchange()
      throws GeneralSecurityException, UnsupportedEncodingException {
    NtlmV1Client client = NtlmV1Client.builder()
        .setUserName(FIXED_USER_NAME)
        .setPassword(FIXED_PASSWORD)
        .setWorkstationName(FIXED_WORKSTATION_NAME)
        .setClientChallenge(hexToBytes(FIXED_CLIENT_CHALLENGE))
        .build();
    NtlmV1Server server = NtlmV1Server.builder()
        .setDomainName(FIXED_DOMAIN_NAME)
        .setLookupPassword(makePasswordDb(FIXED_DOMAIN_NAME, FIXED_USER_NAME, FIXED_PASSWORD))
        .setNegotiateMessage(client.createNegotiateMessage())
        .setServerChallenge(hexToBytes(FIXED_SERVER_CHALLENGE))
        .build();
    assertTrue(finishExchange(client, server));
    assertEquals(FIXED_RESPONSE,
        bytesToHex(client.getAuthenticateMessage().getNtChallengeResponse()));
  }

  private boolean finishExchange(NtlmV1Client client, NtlmV1Server server)
      throws GeneralSecurityException, UnsupportedEncodingException {
    client.setChallengeMessage(server.createChallengeMessage());
    server.setAuthenticateMessage(client.createAuthenticateMessage());
    return server.isClientAuthenticated();
  }

  private PasswordDb makePasswordDb(String domainName, String userName, String password) {
    PasswordDb passwordDb = new PasswordDb();
    passwordDb.setPassword(domainName, userName, password);
    return passwordDb;
  }

  private final class PasswordDb implements Function<NtlmAuthenticate, String> {
    private final Map<String, Map<String, String>> domainMap;

    public PasswordDb() {
      domainMap = Maps.newHashMap();
    }

    public String apply(NtlmAuthenticate authenticate) {
      String domainName = authenticate.getDomainName();
      String userName = authenticate.getUserName();
      return getPassword(domainName, userName);
    }

    private String getPassword(String domainName, String userName) {
      return getPasswordMap(domainName).get(userName);
    }

    public void setPassword(String domainName, String userName, String password) {
      getPasswordMap(domainName).put(userName, password);
    }

    private Map<String, String> getPasswordMap(String domainName) {
      if (domainName == null) {
        domainName = "";
      }
      Map<String, String> passwordMap = domainMap.get(domainName);
      if (passwordMap == null) {
        passwordMap = Maps.newHashMap();
        domainMap.put(domainName, passwordMap);
      }
      return passwordMap;
    }
  }
}
