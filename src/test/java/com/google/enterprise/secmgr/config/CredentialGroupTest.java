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

package com.google.enterprise.secmgr.config;

import static com.google.enterprise.secmgr.config.ConfigTestUtil.jsonArray;
import static com.google.enterprise.secmgr.config.ConfigTestUtil.jsonBinding;
import static com.google.enterprise.secmgr.config.ConfigTestUtil.jsonObject;
import static com.google.enterprise.secmgr.config.ConfigTestUtil.jsonQuote;

import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.servlets.SecurityManagerServletConfig;
import java.util.List;
import junit.framework.TestCase;
import org.apache.commons.lang3.StringUtils;

/**
 * Unit test for CredentialGroup.
 */
public class CredentialGroupTest extends TestCase {

  public CredentialGroupTest() {
    super();
    SecurityManagerServletConfig.initializeGson();
  }

  public void testCg1() {
    runCgTest(makeCg1());
  }

  public void testCg2() {
    runCgTest(makeCg2());
 }

  public void testCg3() {
    runCgTest(makeCg3());
 }

  public void testCg4() {
    runCgTest(makeCg4());
 }

  public void testCgAuthnMechGroups() {
    runCgAuthnMechGroupsTest();
 }

  private void runCgTest(CredentialGroup expected) {
    CredentialGroup cg
        = ConfigSingleton.getGson().fromJson(makeCgString(expected), CredentialGroup.class);
    assertEquals(expected, cg);
  }

  private void runCgAuthnMechGroupsTest() {
    CredentialGroup cgOld = CredentialGroup.builder("cg5", "CG5", false, false, false)
        .addMechanism(AuthnMechGroups.makeForCredentialGroup("cg5"))
        .build();
    AuthnMechanism mechOld = cgOld.getFirstMechanismOfType(AuthnMechGroups.class);
    assertTrue(StringUtils.startsWithIgnoreCase(mechOld.getName(), cgOld.getName()));

    CredentialGroup.Builder cgNewBuilder = CredentialGroup.builder(
        "cg6", "CG6", false, false, false);
    // Add Authn Groups mechanism from cgOld.
    cgNewBuilder.addMechanism(mechOld);
    // Update the Authn Groups Mech Name with new CG name.
    cgNewBuilder.updateAuthnGroupsMechanism(
        AuthnMechGroups.makeForCredentialGroup("cg6"));
    // Build the new CG.
    CredentialGroup cgNew = cgNewBuilder.build();
    AuthnMechanism mechNew = cgNew.getFirstMechanismOfType(AuthnMechGroups.class);
    assertTrue(StringUtils.startsWithIgnoreCase(mechNew.getName(), cgNew.getName()));
  }

  public static CredentialGroup makeCg1() {
    return CredentialGroup.builder("default", "Default", false, false, false)
        .addMechanism(AuthnMechanismTest.makeMech1())
        .addMechanism(AuthnMechanismTest.makeMech2())
        .build();
  }

  public static CredentialGroup makeCg2() {
    return CredentialGroup.builder("cg2", "CG2", false, false, false)
        .addMechanism(AuthnMechanismTest.makeMech3())
        .build();
  }

  public static CredentialGroup makeCg3() {
    return CredentialGroup.builder("default", "Default", false, false, false)
        .addMechanism(AuthnMechanismTest.makeMech1())
        .addMechanism(AuthnMechGroups.makeForCredentialGroup("default"))
        .build();
  }

  public static CredentialGroup makeCg4() {
    return CredentialGroup.builder("cg4", "CG4", false, false, false)
        .addMechanism(AuthnMechGroups.makeForCredentialGroup("cg4"))
        .build();
  }

  public static String makeCgString(CredentialGroup cg) {
    List<String> mechs = Lists.newArrayList();
    for (AuthnMechanism mech : cg.getMechanisms()) {
      mechs.add(AuthnMechanismTest.makeMechString(mech));
    }
    return jsonObject(
        jsonBinding("name", jsonQuote(cg.getName())),
        jsonBinding("displayName", jsonQuote(cg.getDisplayName())),
        jsonBinding("requiresUsername", jsonQuote(cg.getRequiresUsername())),
        jsonBinding("requiresPassword", jsonQuote(cg.getRequiresPassword())),
        jsonBinding("isOptional", jsonQuote(cg.getIsOptional())),
        jsonBinding("mechanisms", jsonArray(mechs)));
  }
}
