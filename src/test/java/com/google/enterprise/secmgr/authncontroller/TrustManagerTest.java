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

package com.google.enterprise.secmgr.authncontroller;

import com.google.common.io.Files;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.enterprise.supergsa.security.AclPrincipals;
import com.google.protobuf.TextFormat;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import org.joda.time.DateTimeUtils;

/**
 * Tests for {@link TrustManager}.
 */
public final class TrustManagerTest extends SecurityManagerTestCase {

  private final TrustManager manager;

  private String s0 =
      "  scope: 1\n" +
      "  name: \"CRACK_CS_GET\"\n" +
      "  name_space: \"Default\"\n" +
      "  case_sensitive: 0\n";
  private AclPrincipal user0;

  private String s1 =
      "  scope: 1\n" +
      "  name: \"user1\"\n" +
      "  name_space: \"cg1\"\n" +
      "  domain <\n" +
      "    name: \"domain1\"\n" +
      "    type: 0\n" +
      "  >\n" +
      "  case_sensitive: 0\n";
  private AclPrincipal user1;

  private String s2 =
      "  scope: 1\n" +
      "  name: \"USER2\"\n" +
      "  name_space: \"Default\"\n" +
      "  case_sensitive: 0\n";
  private AclPrincipal user2;

  private String s3 =
      "  scope: 1\n" +
      "  name: \"moma-search-prod\"\n" +
      "  name_space: \"cg1\"\n" +
      "  case_sensitive: 1\n";
  private AclPrincipal user3;

  private String s4 =
      "  scope: 2\n" +
      "  name: \"moma-search-prod\"\n" +
      "  name_space: \"cg1\"\n" +
      "  case_sensitive: 0\n";
  private AclPrincipal group;

  private ExportedState user0State;
  private ExportedState user1State;
  private ExportedState user2State;
  private ExportedState user3State;
  private ExportedState groupState;

  public TrustManagerTest() {
    manager = TrustManager.class.cast(
            ConfigSingleton.getInstance(TrustManager.class));
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();
    AclPrincipal.Builder builder = AclPrincipal.newBuilder();
    TextFormat.getParser().merge(s0, builder);
    user0 = builder.build();
    builder.clear();
    TextFormat.getParser().merge(s1, builder);
    user1 = builder.build();
    builder.clear();
    TextFormat.getParser().merge(s2, builder);
    user2 = builder.build();
    builder.clear();
    TextFormat.getParser().merge(s3, builder);
    user3 = builder.build();
    builder.clear();
    TextFormat.getParser().merge(s4, builder);
    group = builder.build();

    manager.setConfFile("trust.enterprise");

    user0State = getState("AuthNInfoUser0.json");
    user1State = getState("AuthNInfoUser1.json");
    user2State = getState("AuthNInfoUser2.json");
    user3State = getState("AuthNInfoUser3.json");
    groupState = getState("AuthNInfoGroup.json");

    addTearDown(new TearDown() {
      @Override
      public void tearDown() throws Exception {
        reset();
      }
    });
  }

  private void reset() {
    manager.reset();
    DateTimeUtils.setCurrentMillisSystem();
  }

  private ExportedState getState(String filename) throws IOException {
    File configFile = FileUtil.getContextFile(filename);
    String jsonAuthnInfo = Files.asCharSource(configFile, Charset.defaultCharset()).read();
    return ExportedState.fromJsonString(jsonAuthnInfo);
  }

  public void testTrust() throws IOException {
    AclPrincipals principals = AclPrincipals.newBuilder()
        .addPrincipals(user0)
        .addPrincipals(user1)
        .addPrincipals(user2)
        .addPrincipals(user3)
        .addPrincipals(group)
        .build();

    File tmpFile = File.createTempFile(getClass().getName() + "-trust", ".tmp");
    // ../testdata/trust.enterprise is copied from the file generated this way.
    manager.writeToFile(principals, tmpFile.getCanonicalPath());
    manager.setConfFile(tmpFile.getCanonicalPath());
    manager.load();
    assertTrue(manager.isTrusted(user1State));
    assertFalse(manager.isTrusted(user2State));
    assertTrue(manager.isTrusted(user3State));
    assertFalse(manager.isTrusted(user0State));
    assertTrue(manager.isTrusted(groupState));

    manager.reset();
    assertFalse(manager.isTrusted(user1State));
    assertFalse(manager.isTrusted(user2State));
    assertFalse(manager.isTrusted(user3State));
    assertFalse(manager.isTrusted(user0State));
    assertFalse(manager.isTrusted(groupState));
  }
}
