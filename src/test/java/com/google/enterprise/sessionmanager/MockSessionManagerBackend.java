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
package com.google.enterprise.sessionmanager;

import com.google.common.base.CharMatcher;
import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTimeUtils;

/**
 * Mocks the complex Kerberos functions of Session Manager for use in testing.
 *
 */
public class MockSessionManagerBackend extends BackendFilesBase {

  private String identity = "";
  private boolean kerberosEnabled = false;
  
  public MockSessionManagerBackend(Settings settings) {
    super(settings);
  }

  public MockSessionManagerBackend() {
    super(new Settings());
  }

  public void enableKerberos(boolean enable) {
    kerberosEnabled = enable;
  }

  // Returns the identity contained inside the SPNEGO blob (for tests).
  @Override
  public KerberosId storeKrb5Identity(String sessionId, String spnegoBlob) {
    // 20min
    long expirationTime = DateTimeUtils.currentTimeMillis() / 1000 + 60 * 20;
    identity =
        StringUtils.removeStart(
            CharMatcher.whitespace().trimFrom(spnegoBlob), "fake_spnego_header: ");
    return new KerberosId(identity, expirationTime);
  }

  @Override
  public KeyMaterial getKrb5TokenForServer(String sessionId, String server) {
      return new KeyMaterial("fake_spnego_blob_for_tests",
      "fake_key_for_tests");
  }

  @Override
  public String getKrb5Identity(String sessionId) {
    return identity;
  }

  @Override
  public String getKrb5CcacheFilename(String sessionId)
      throws IndexOutOfBoundsException {
    return "/tmp/fake_krb5_ccache";
  }

  @Override
  public String parseKrb5Keytab(String filepath) {
    return "user@domain.company.com";
  }

  @Override
  public String getKrb5ServerNameIfEnabled() {
    if (kerberosEnabled) { return "server@domain.company.com"; }
    return null;
  }

}