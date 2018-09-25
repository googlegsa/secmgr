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

import java.io.UnsupportedEncodingException;
import java.util.EnumSet;
import junit.framework.TestCase;

/**
 * A unit test to confirm that an NTLM authenticate message is properly encoded.
 */
public final class NtlmAuthenticateTest extends TestCase {
  private static final String DOMAIN_NAME = "MYDOMAIN.COM";
  private static final String USER_NAME = "mememe";
  private static final String WORKSTATION_NAME = "MYWORKSTATION";

  public void testEncodeDecode() throws UnsupportedEncodingException {
    byte[] response = NtlmCrypto.generateNonce(24);
    NtlmAuthenticate message
        = NtlmAuthenticate.make(response, response, DOMAIN_NAME, USER_NAME, WORKSTATION_NAME, null,
            EnumSet.of(NtlmSspFlag.NEGOTIATE_UNICODE), null, null);
    byte[] encoded = message.encode();
    NtlmAuthenticate decoded = NtlmAuthenticate.decode(encoded, false);
    assertEquals(message, decoded);
  }
}
