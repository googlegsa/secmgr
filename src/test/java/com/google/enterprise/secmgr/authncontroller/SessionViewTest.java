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
package com.google.enterprise.secmgr.authncontroller;

import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.config.AuthnMechBasic;
import com.google.enterprise.secmgr.config.AuthnMechGroups;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

import java.io.IOException;

/**
 * Tests of {@link SessionView} and its descendants.
 */
public final class SessionViewTest extends SecurityManagerTestCase {
  private static final String BASIC_NAME_1 = "basic-1";
  private static final String BASIC_URL_1 = "http://example.com/basic-1";
  private static final AuthnMechanism MECH_1 = AuthnMechBasic.make(BASIC_NAME_1, BASIC_URL_1);
  private static final AuthnMechanism MECHGROUPS1 = AuthnMechGroups.make(
      "groups1", AuthnMechanism.NO_TIME_LIMIT, AuthnMechGroups.getDefaultTrustDuration());
  private static final AuthnMechanism MECHGROUPS2 = AuthnMechGroups.make(
      "groups2", AuthnMechanism.NO_TIME_LIMIT, AuthnMechGroups.getDefaultTrustDuration());
  
  private static final String CG_NAME_1 = "cg-1";
  private static final CredentialGroup CG_1
      = CredentialGroup.builder(CG_NAME_1, CG_NAME_1, false, false, false).build();

  private static final String CG_NAME_2 = "cg-2";
  private static final CredentialGroup CG_2
      = CredentialGroup.builder(CG_NAME_2, CG_NAME_2, false, false, false).build();
  
  private static final Credential EMPTY_USERNAME = AuthnPrincipal.make("", "");
  private static final Credential EMPTY_PASSWORD = CredPassword.make("");

  public void testOptionalOverridesRequiresUsername()
      throws IOException {
    CredentialGroup cg = CredentialGroup.builder(CG_1)
        .setRequiresUsername(true)
        .setIsOptional(true)
        .addMechanism(MECHGROUPS1)
        .addMechanism(MECH_1)
        .build();
    ConfigSingleton.setConfig(makeConfig(ImmutableList.of(cg)));
    AuthnSession session = AuthnSession.newInstance();
    assertFalse(session.getSnapshot().getView(cg).isSatisfied(false));
    session.addCredentials(MECH_1, EMPTY_USERNAME, EMPTY_PASSWORD);
    assertTrue(session.getSnapshot().getView(cg).isSatisfied(true));
  }

  public void testOptionalOverridesRequiresPassword()
      throws IOException {
    CredentialGroup cg = CredentialGroup.builder(CG_1)
        .setRequiresPassword(true)
        .setIsOptional(true)
        .addMechanism(MECHGROUPS1)
        .addMechanism(MECH_1)
        .build();
    ConfigSingleton.setConfig(makeConfig(ImmutableList.of(cg)));
    AuthnSession session = AuthnSession.newInstance();
    assertFalse(session.getSnapshot().getView(cg).isSatisfied(false));
    session.addCredentials(MECH_1, EMPTY_USERNAME, EMPTY_PASSWORD);
    assertTrue(session.getSnapshot().getView(cg).isSatisfied(true));
  }
  
  public void testEmptyCredentialGroup() throws IOException {
    CredentialGroup cg1 = CredentialGroup.builder(CG_1)
        .addMechanism(MECHGROUPS1)
        .build();
    CredentialGroup cg2 = CredentialGroup.builder(CG_2)
        .addMechanism(MECHGROUPS2)
        .addMechanism(MECH_1)
        .build();
    ConfigSingleton.setConfig(makeConfig(ImmutableList.of(cg1, cg2)));
    AuthnSession session = AuthnSession.newInstance();
    Verification verification1
    = Verification.verified(Verification.NEVER_EXPIRES, AuthnPrincipal.make("joe",
        "cg2"),
        CredPassword.make("biden"));
    session.addVerification(MECH_1.getAuthority(), verification1);
    assertTrue(session.getSnapshot().getView().isSatisfied(true));
    assertFalse(session.getSnapshot().getView(cg1).isSatisfied(true));
    assertTrue(session.getSnapshot().getView(cg2).isSatisfied(true));
  }
}
