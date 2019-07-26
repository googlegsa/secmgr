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

package com.google.enterprise.secmgr.authncontroller;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.authncontroller.AuthnSession.AuthnState;
import com.google.enterprise.secmgr.config.AuthnMechBasic;
import com.google.enterprise.secmgr.config.AuthnMechForm;
import com.google.enterprise.secmgr.config.AuthnMechNtlm;
import com.google.enterprise.secmgr.config.AuthnMechSaml;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.identity.VerificationStatus;
import com.google.enterprise.secmgr.modules.SamlCredentialsGatherer;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Set;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.SAMLObject;

/**
 * Generic tests for the authentication session, which is a state machine with
 * associated information.  These tests check that access to the session info is
 * enabled or disabled according the current session state.  They also check
 * that transitions from one state to another are allowed or forbidden as
 * appropriate.
 */
public class AuthnSessionTest extends SecurityManagerTestCase {

  private static final String AUTHN_ENTRY_URL = "http://localhost/universalloginform";
  private static final String SAMPLE_URL_1 = "http://localhost/domain1/sample";
  private static final String SAMPLE_URL_2 = "http://localhost/domain2/sample";
  private static final String ENTITY_ID_3 = "http://localhost/domain3/entityId";

  private SecurityManagerConfig config;
  private AuthnSession session;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    config
        = makeConfig(
            Lists.newArrayList(
                CredentialGroup.builder("group1", "group1 display", true, true, false)
                .addMechanism(AuthnMechBasic.make("mech1", SAMPLE_URL_1))
                .addMechanism(AuthnMechForm.make("mech2", SAMPLE_URL_2))
                .build(),
                CredentialGroup.builder("group2", "group2 display", true, true, false)
                .addMechanism(AuthnMechSaml.make("mech3", ENTITY_ID_3))
                .build()));
    session = AuthnSession.getInstance(config);
  }

  /**
   * Test access and transitions from the IDLE state.
   */
  public void testIdleState() throws IOException {
    newIdleSession();
    assertEquals(AuthnState.IDLE, session.getState());

    // We're not allowed to access generic authentication state.
    denySamlSsoContext();
    denyAuthnEntryUrl();
    denyGetPromptCounter();

    // We're not allowed to increment the prompt counter.
    denyIncrementPromptCounter();

    // We're not allowed to access ULF or credentials-gatherer state.
    denyUniversalLoginForm();
    denyCredentialsGathererElement();

    // Transition allowed: IDLE->IDLE
    allowIdleTransition();

    // Transition allowed: IDLE->AUTHENTICATING
    newIdleSession();
    allowAuthenticatingTransition();

    // Return forbidden: IDLE->AUTHENTICATING
    newIdleSession();
    denyAuthenticatingReturnTransition();

    // Transition forbidden: IDLE->IN_UL_FORM
    newIdleSession();
    denyInUniversalLoginFormTransition();

    // Transition forbidden: IDLE->IN_CREDENTIALS_GATHERER
    newIdleSession();
    denyInCredentialsGathererTransition();
  }

  /**
   * Test access and transitions from the AUTHENTICATING state.
   */
  public void testAuthenticatingState() throws IOException {
    newAuthenticatingSession();
    assertEquals(AuthnState.AUTHENTICATING, session.getState());

    // We're allowed to access generic authentication state.
    allowSamlSsoContext();
    allowAuthnEntryUrl();
    allowGetPromptCounter();

    // We're allowed to increment the prompt counter.
    allowIncrementPromptCounter();

    // We're not allowed to access ULF or credentials-gatherer state.
    denyUniversalLoginForm();
    denyCredentialsGathererElement();

    // Transition allowed: AUTHENTICATING->IDLE
    allowIdleTransition();

    // Transition forbidden: AUTHENTICATING->AUTHENTICATING
    newAuthenticatingSession();
    denyAuthenticatingTransition();

    // Return forbidden: AUTHENTICATING->AUTHENTICATING
    newAuthenticatingSession();
    denyAuthenticatingReturnTransition();

    // Transition allowed: AUTHENTICATING->IN_UL_FORM
    newAuthenticatingSession();
    allowInUniversalLoginFormTransition();

    // Transition allowed: AUTHENTICATING->IN_CREDENTIALS_GATHERER
    newAuthenticatingSession();
    allowInCredentialsGathererTransition();
  }

  /**
   * Test access and transitions from the IN_UL_FORM state.
   */
  public void testInUniversalLoginFormState() throws IOException {
    newInUniversalLoginFormSession();
    assertEquals(AuthnState.IN_UL_FORM, session.getState());

    // We're allowed to access generic authentication state.
    allowSamlSsoContext();
    allowAuthnEntryUrl();
    allowGetPromptCounter();

    // We're not allowed to increment the counter.
    denyIncrementPromptCounter();

    // We're allowed to access the ULF.
    allowUniversalLoginForm();

    // We're not allowed to access the credentials-gatherer state.
    denyCredentialsGathererElement();

    // Transition allowed: IN_UL_FORM->IDLE (only for error recovery)
    allowIdleTransition();

    // Transition forbidden: IN_UL_FORM->AUTHENTICATING
    newInUniversalLoginFormSession();
    denyAuthenticatingTransition();

    // Return allowed: IN_UL_FORM->AUTHENTICATING
    newInUniversalLoginFormSession();
    allowAuthenticatingReturnTransition();

    // Transition forbidden: IN_UL_FORM->IN_UL_FORM
    newInUniversalLoginFormSession();
    denyInUniversalLoginFormTransition();

    // Transition forbidden: IN_UL_FORM->IN_CREDENTIALS_GATHERER
    newInUniversalLoginFormSession();
    denyInCredentialsGathererTransition();
  }

  /**
   * Test access and transitions from the IN_CREDENTIALS_GATHERER state.
   */
  public void testInCredentialsGathererState() throws IOException {
    newInCredentialsGathererSession();
    assertEquals(AuthnState.IN_CREDENTIALS_GATHERER, session.getState());

    // We're allowed to access generic authentication state.
    allowSamlSsoContext();
    allowAuthnEntryUrl();
    allowGetPromptCounter();

    // We're not allowed to increment the counter.
    denyIncrementPromptCounter();

    // We're not allowed to access the ULF.
    denyUniversalLoginForm();

    // We're allowed to access the credentials-gatherer state.
    allowCredentialsGathererElement();

    // Transition allowed: IN_CREDENTIALS_GATHERER->IDLE (only for error recovery)
    allowIdleTransition();

    // Transition forbidden: IN_CREDENTIALS_GATHERER->AUTHENTICATING
    newInCredentialsGathererSession();
    denyAuthenticatingTransition();

    // Return allowed: IN_CREDENTIALS_GATHERER->AUTHENTICATING
    newInCredentialsGathererSession();
    allowAuthenticatingReturnTransition();

    // Transition forbidden: IN_CREDENTIALS_GATHERER->IN_UL_FORM
    newInCredentialsGathererSession();
    denyInUniversalLoginFormTransition();

    // Transition forbidden: IN_CREDENTIALS_GATHERER->IN_CREDENTIALS_GATHERER
    newInCredentialsGathererSession();
    denyInCredentialsGathererTransition();
  }

  private void allowSamlSsoContext() {
    assertNotNull(session.getSamlSsoContext());
  }

  private void denySamlSsoContext() {
    try {
      session.getSamlSsoContext();
      fail("Access to SAML SSO context was allowed but should have been denied");
    } catch (IllegalStateException e) {
      // pass
    }
  }

  private void allowAuthnEntryUrl() {
    assertNotNull(session.getAuthnEntryUrl());
  }

  private void denyAuthnEntryUrl() {
    try {
      session.getAuthnEntryUrl();
      fail("Access to authn entry URL was allowed but should have been denied");
    } catch (IllegalStateException e) {
      // pass
    }
  }

  private void allowGetPromptCounter() {
    assertEquals(0, session.getPromptCounter());
  }

  private void denyGetPromptCounter() {
    try {
      session.getPromptCounter();
      fail("Access to prompt counter was allowed but should have been denied");
    } catch (IllegalStateException e) {
      // pass
    }
  }

  private void allowIncrementPromptCounter() {
    assertEquals(1, session.incrementPromptCounter());
  }

  private void denyIncrementPromptCounter() {
    try {
      session.incrementPromptCounter();
      fail("Incrementing of prompt counter was allowed but should have been denied");
    } catch (IllegalStateException e) {
      // pass
    }
  }

  private void allowUniversalLoginForm() {
    assertNotNull(session.getUniversalLoginForm());
  }

  private void denyUniversalLoginForm() {
    try {
      session.getUniversalLoginForm();
      fail("Access to the ULF was allowed but should have been denied");
    } catch (IllegalStateException e) {
      // pass
    }
  }

  private void allowCredentialsGathererElement() {
    session.getCredentialsGathererElement();
  }

  private void denyCredentialsGathererElement() {
    try {
      session.getCredentialsGathererElement();
      fail("Access to credential-gatherer element was allowed but should have been denied");
    } catch (IllegalStateException e) {
      // pass
    }
  }

  private void newIdleSession() {
    session = AuthnSession.getInstance(config);
  }

  private void allowIdleTransition() {
    session.setStateIdle();
    assertEquals(AuthnState.IDLE, session.getState());
  }

  private void newAuthenticatingSession() throws IOException {
    newIdleSession();
    MessageContext<SAMLObject> context = OpenSamlUtil.makeSamlMessageContext();
    session.setStateAuthenticating(new URL(AUTHN_ENTRY_URL), context);
  }

  private void allowAuthenticatingTransition() throws IOException {
    MessageContext<SAMLObject> context = OpenSamlUtil.makeSamlMessageContext();
    session.setStateAuthenticating(new URL(AUTHN_ENTRY_URL), context);
    assertEquals(AuthnState.AUTHENTICATING, session.getState());
  }

  private void denyAuthenticatingTransition() throws IOException {
    try {
      MessageContext<SAMLObject> context = OpenSamlUtil.makeSamlMessageContext();
      session.setStateAuthenticating(new URL(AUTHN_ENTRY_URL), context);
      fail("Transition to AUTHENTICATING state was allowed but should have been denied");
    } catch (IllegalStateException e) {
      // pass
    }
  }

  private void allowAuthenticatingReturnTransition() {
    session.returnToAuthenticatingState();
    assertEquals(AuthnState.AUTHENTICATING, session.getState());
  }

  private void denyAuthenticatingReturnTransition() {
    try {
      session.returnToAuthenticatingState();
      fail("Returning to AUTHENTICATING state was allowed but should have been denied");
    } catch (IllegalStateException e) {
      // pass
    }
  }

  private void newInUniversalLoginFormSession() throws IOException {
    newAuthenticatingSession();
    session.setStateInUniversalLoginForm();
  }

  private void allowInUniversalLoginFormTransition() throws IOException {
    session.setStateInUniversalLoginForm();
    assertEquals(AuthnState.IN_UL_FORM, session.getState());
  }

  private void denyInUniversalLoginFormTransition() throws IOException {
    try {
      session.setStateInUniversalLoginForm();
      fail("Transition to IN_UL_FORM state was allowed but should have been denied");
    } catch (IllegalStateException e) {
      // pass
    }
  }

  private void newInCredentialsGathererSession() throws IOException {
    newAuthenticatingSession();
    session.setStateInCredentialsGatherer(getCredentialsGatherers());
  }

  private void allowInCredentialsGathererTransition() {
    session.setStateInCredentialsGatherer(getCredentialsGatherers());
    assertEquals(AuthnState.IN_CREDENTIALS_GATHERER, session.getState());
  }

  private void denyInCredentialsGathererTransition() {
    try {
      session.setStateInCredentialsGatherer(getCredentialsGatherers());
      fail("Transition to IN_CREDENTIALS_GATHERER state was allowed but should have been denied");
    } catch (IllegalStateException e) {
      // pass
    }
  }

  private static ImmutableSet<CredentialsGatherer> getCredentialsGatherers() {
    return ImmutableSet.<CredentialsGatherer>of(
        ConfigSingleton.getInstance(SamlCredentialsGatherer.class));
  }

  // Tests that verifications are shared among the mechanisms in a credential
  // group but that verification status is not.
  public void testVerificationSharing() {
    AuthnMechanism mech1 = AuthnMechForm.make("mech1", "http://mech1.example.com/", 20000, 300000);
    AuthnMechanism mech2 = AuthnMechBasic.make("mech2", "http://mech2.example.com/", 30000, 600000);
    AuthnMechanism mech3 = AuthnMechNtlm.make("mech3", "http://mech3.example.com/", 40000, 600000);
    AuthnMechanism mech4 = AuthnMechSaml.make("mech4", "http://example.com/saml/");
    List<AuthnMechanism> mechs = ImmutableList.of(mech1, mech2, mech3, mech4);
    AuthnSession session
        = AuthnSession.getInstance(
            makeConfig(
                ImmutableList.of(
                    CredentialGroup.builder("cg1", "Credential Group #1", true, false, false)
                    .addMechanism(mech1)
                    .addMechanism(mech2)
                    .build(),
                    CredentialGroup.builder("cg2", "Credential Group #2", true, false, true)
                    .addMechanism(mech3)
                    .addMechanism(mech4)
                    .build())));
    Verification verification1
        = Verification.verified(Verification.NEVER_EXPIRES, AuthnPrincipal.make("joe",
            "cg1"),
            CredPassword.make("biden"));
    Verification verification2
        = Verification.verified(Verification.NEVER_EXPIRES, AuthnPrincipal.make("joe", 
            "cg1"));
    Verification verification3
        = Verification.verified(Verification.NEVER_EXPIRES, AuthnPrincipal.make("jim", 
            "cg1"));
    Set<Verification> verifications0 = ImmutableSet.of();
    Set<Verification> verifications1 = ImmutableSet.of(verification1);
    Set<Verification> verifications2 = ImmutableSet.of(verification1, verification2);
    Set<Verification> verifications3 = ImmutableSet.of(verification3);

    checkVerifications(session, mechs,
        ImmutableList.of(
            VerificationStatus.INDETERMINATE,
            VerificationStatus.INDETERMINATE,
            VerificationStatus.INDETERMINATE,
            VerificationStatus.INDETERMINATE),
        ImmutableList.of(
            verifications0,
            verifications0,
            verifications0,
            verifications0));

    session.addVerification(mech1.getAuthority(), verification1);
    checkVerifications(session, mechs,
        ImmutableList.of(
            VerificationStatus.VERIFIED,
            VerificationStatus.INDETERMINATE,
            VerificationStatus.INDETERMINATE,
            VerificationStatus.INDETERMINATE),
        ImmutableList.of(
            verifications1,
            verifications1,
            verifications0,
            verifications0));

    session.addVerification(mech2.getAuthority(), verification2);
    checkVerifications(session, mechs,
        ImmutableList.of(
            VerificationStatus.VERIFIED,
            VerificationStatus.VERIFIED,
            VerificationStatus.INDETERMINATE,
            VerificationStatus.INDETERMINATE),
        ImmutableList.of(
            verifications2,
            verifications2,
            verifications0,
            verifications0));

    session.addVerification(mech3.getAuthority(), verification3);
    checkVerifications(session, mechs,
        ImmutableList.of(
            VerificationStatus.VERIFIED,
            VerificationStatus.VERIFIED,
            VerificationStatus.VERIFIED,
            VerificationStatus.INDETERMINATE),
        ImmutableList.of(
            verifications2,
            verifications2,
            verifications3,
            verifications3));
  }

  private void checkVerifications(AuthnSession session, List<AuthnMechanism> mechs,
      List<VerificationStatus> expectedStatus, List<Set<Verification>> expectedSet) {
    SessionSnapshot snapshot = session.getSnapshot();
    for (int i = 0; i < mechs.size(); i += 1) {
      assertEquals(expectedStatus.get(i), snapshot.getView(mechs.get(i)).getVerificationStatus());
      assertEquals(expectedSet.get(i), snapshot.getView(mechs.get(i)).getVerifications());
    }
  }
}
