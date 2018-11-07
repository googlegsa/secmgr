// Copyright 2011 Google Inc.
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

import com.google.common.base.Predicates;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.SetMultimap;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.config.AuthnAuthority;
import com.google.enterprise.secmgr.config.AuthnMechBasic;
import com.google.enterprise.secmgr.config.AuthnMechForm;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.generators.Generators;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.GroupMemberships;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.servlets.SecurityManagerServletConfig;
import com.google.gson.Gson;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import junit.framework.TestCase;

/**
 * Unit tests for {@link AuthnSessionState}.
 */
public final class AuthnSessionStateTest extends TestCase {
  private static final AuthnAuthority AUTHORITY1 = AuthnAuthority.make();
  private static final AuthnAuthority AUTHORITY2 = AuthnAuthority.make();
  private static final ImmutableList<AuthnAuthority> AUTHORITIES =
      ImmutableList.of(AUTHORITY1, AUTHORITY2);

  private static final GCookie COOKIE1 = GCookie.make("name1", "value1");
  private static final GCookie COOKIE2 = GCookie.make("name2", "value2");

  private static final Credential CREDENTIAL1 = AuthnPrincipal.make("user1", "cg1", "domain1");
  private static final Credential CREDENTIAL2 = AuthnPrincipal.make("user2", "cg2", "domain2");
  private static final AuthnMechanism mech11 = 
      AuthnMechForm.make("mech11", "http://example.com/sample11");  
  private final AuthnMechanism mech12 =
      AuthnMechBasic.make("mech12", "http://google.com/sample12");
  private static final AuthnMechanism mech21 = 
      AuthnMechForm.make("mech21", "http://example.com/sample21");
  private static final AuthnMechanism mech22 = 
      AuthnMechForm.make("mech22", "http://example.com/sample22");
  
  private static final Verification VERIFICATION1
      = Verification.verified(Verification.NEVER_EXPIRES,
          AuthnPrincipal.make("user3", "cg3"),
          CredPassword.make("pass3"));
  private static final Verification VERIFICATION2
      = Verification.verified(Verification.NEVER_EXPIRES,
          AuthnPrincipal.make("user4", "cg4"),
          CredPassword.make("pass4"), 
          GroupMemberships.make(
              ImmutableSet.of(Group.make("group1", "cg4"), Group.make("group2", "cg4"))));
  private static final Verification VERIFICATION3
      = Verification.verified(Verification.NEVER_EXPIRES,          
          GroupMemberships.make(
          ImmutableSet.of(Group.make("group1", "cg4"), Group.make("group2", "cg4"), 
                          Group.make("group3", "cg4"))));
  private static final Verification VERIFICATION4
      = Verification.verified(Verification.NEVER_EXPIRES,
          AuthnPrincipal.make("user4", "cg3"),
          CredPassword.make("pass4"), 
          GroupMemberships.make(ImmutableSet.of(Group.make("group1", "cg3"))));

  private static final ImmutableList<CredentialGroup> CGS = ImmutableList.of();

  @Override
  public void setUp() {
    SecurityManagerServletConfig.initializeGson();    
  }

  public void testCookies() {
    runSingleTests(new CookieTester());
  }

  public void testCredentials() {
    runSingleTests(new CredentialTester());
  }

  public void testVerifications() {
    runSingleTests(new VerificationTester());
  }

  private enum TestOperation { ADD, REMOVE }

  /**
   * A model of an AuthnSessionState operation.
   */
  private static final class TestInstruction<T> {
    final TestOperation operation;
    final AuthnAuthority authority;
    final T object;

    TestInstruction(TestOperation operation, AuthnAuthority authority, T object) {
      this.operation = operation;
      this.authority = authority;
      this.object = object;
    }
  }

  /**
   * A tester for some AuthnSessionState operations.
   *
   * @param <T> The type of objects being manipulated by the operations.
   */
  private abstract static class Tester<T> {
    /**
     * Gets some objects to run the test over.
     */
    public abstract List<T> getObjects();

    /**
     * Executes a single instruction on an AuthnSessionState instance.
     *
     * @param instruction An instruction to execute.
     * @param state An AuthnSessionState instance to execute the instruction on.
     * @return The AuthnSessionState instance produced by executing the instruction.
     */
    public abstract AuthnSessionState execute(TestInstruction<T> instruction,
        AuthnSessionState state);

    /**
     * Executes a sequence of instructions on an AuthnSessionState instance.
     *
     * @param instructions Some instructions to execute (in order).
     * @param state An AuthnSessionState instance to execute the instructions on.
     * @return The AuthnSessionState instance produced by executing the instructions.
     */
    public AuthnSessionState execute(Iterable<TestInstruction<T>> instructions,
        AuthnSessionState state) {
      for (TestInstruction<T> instruction : instructions) {
        state = execute(instruction, state);
      }
      return state;
    }

    /**
     * Executes a single instruction on a model.
     *
     * @param instruction An instruction to execute.
     * @param model A map that models the internal state of an AuthnSessionState instance.
     */
    public abstract void execute(TestInstruction<T> instruction,
        SetMultimap<AuthnAuthority, T> model);

    /**
     * Executes a sequence of instructions on a model.
     *
     * @param instructions Some instruction to execute (in order).
     * @param model A map that models the internal state of an AuthnSessionState instance.
     */
    public void execute(Iterable<TestInstruction<T>> instructions,
        SetMultimap<AuthnAuthority, T> model) {
      for (TestInstruction<T> instruction : instructions) {
        execute(instruction, model);
      }
    }

    /**
     * Given an AuthnSessionState instance and a corresponding model, tests that
     * they are the same.
     *
     * @param model A map that models the internal state of an AuthnSessionState instance.
     * @param state An AuthnSessionState instance.
     */
    public void expect(SetMultimap<AuthnAuthority, T> model, AuthnSessionState state) {
      AuthnSessionState.Summary summary = state.computeSummary(CGS);
      for (AuthnAuthority authority : AUTHORITIES) {
        assertEquals(model.get(authority), get(summary, authority));
      }
    }

    /**
     * Gets the result set for an AuthnSessionState instance and a particular authority.
     *
     * @param summary A summary for an AuthnSessionState instance.
     * @param authority An authority to get the result set for.
     * @return A set of the results for that authority.
     */
    public abstract Set<T> get(AuthnSessionState.Summary summary, AuthnAuthority authority);
  }

  /**
   * A tester for the cookie operations of AuthnSessionState.
   */
  private static final class CookieTester extends Tester<GCookie> {
    @Override
    public List<GCookie> getObjects() {
      return ImmutableList.of(COOKIE1, COOKIE2);
    }

    @Override
    public AuthnSessionState execute(TestInstruction<GCookie> instruction,
        AuthnSessionState state) {
      switch (instruction.operation) {
        case ADD: return state.addCookie(instruction.authority, instruction.object);
        case REMOVE: return state.removeCookie(instruction.authority, instruction.object);
        default: throw new IllegalStateException();
      }
    }

    @Override
    public void execute(TestInstruction<GCookie> instruction,
        SetMultimap<AuthnAuthority, GCookie> model) {
      switch (instruction.operation) {
        case ADD: model.put(instruction.authority, instruction.object); break;
        case REMOVE: model.remove(instruction.authority, instruction.object); break;
        default: throw new IllegalStateException();
      }
    }

    @Override
    public Set<GCookie> get(AuthnSessionState.Summary summary, AuthnAuthority authority) {
      return summary.getCookies(Predicates.equalTo(authority));
    }
  }

  /**
   * A tester for the credential operations of AuthnSessionState.
   */
  private static final class CredentialTester extends Tester<Credential> {
    @Override
    public List<Credential> getObjects() {
      return ImmutableList.of(CREDENTIAL1, CREDENTIAL2);
    }

    @Override
    public AuthnSessionState execute(TestInstruction<Credential> instruction,
        AuthnSessionState state) {
      switch (instruction.operation) {
        case ADD: return state.addCredential(instruction.authority, instruction.object);
        case REMOVE: return state.removeCredential(instruction.authority, instruction.object);
        default: throw new IllegalStateException();
      }
    }

    @Override
    public void execute(TestInstruction<Credential> instruction,
        SetMultimap<AuthnAuthority, Credential> model) {
      switch (instruction.operation) {
        case ADD:
          Iterator<Credential> iter = model.get(instruction.authority).iterator();
          while (iter.hasNext()) {
            if (instruction.object.getClass().isInstance(iter.next())) {
              iter.remove();
            }
          }
          model.put(instruction.authority, instruction.object);
          break;
        case REMOVE:
          model.remove(instruction.authority, instruction.object);
          break;
        default:
          throw new IllegalStateException();
      }
    }

    @Override
    public Set<Credential> get(AuthnSessionState.Summary summary, AuthnAuthority authority) {
      return summary.getCredentials(Predicates.equalTo(authority));
    }
  }

  /**
   * A tester for the verification operations of AuthnSessionState.
   */
  private static final class VerificationTester extends Tester<Verification> {
    @Override
    public List<Verification> getObjects() {
      return ImmutableList.of(VERIFICATION1, VERIFICATION2);
    }

    @Override
    public AuthnSessionState execute(TestInstruction<Verification> instruction,
        AuthnSessionState state) {
      switch (instruction.operation) {
        case ADD: return state.addVerification(instruction.authority, instruction.object);
        case REMOVE: return state.removeVerification(instruction.authority, instruction.object);
        default: throw new IllegalStateException();
      }
    }

    @Override
    public void execute(TestInstruction<Verification> instruction,
        SetMultimap<AuthnAuthority, Verification> model) {
      switch (instruction.operation) {
        case ADD:
          forceRemovals(instruction.object.getCredentials(), model.get(instruction.authority));
          model.put(instruction.authority, instruction.object);
          break;
        case REMOVE:
          model.remove(instruction.authority, instruction.object);
          break;
        default:
          throw new IllegalStateException();
      }
    }

    /**
     * Removes any verifications that will be invalidated by adding some given
     * credentials.
     *
     * @param credentials Some credentials that are about to be added.
     * @param verifications Some verifications to modify.
     */
    static void forceRemovals(Iterable<Credential> credentials,
        final Set<Verification> verifications) {
      Iterator<Verification> iter = verifications.iterator();
      while (iter.hasNext()) {
        if (shouldBeRemoved(iter.next(), credentials)) {
          iter.remove();
        }
      }
    }

    /**
     * Will a given verification be invalidated by adding some given
     * credentials?
     *
     * @param verification A verification to test.
     * @param credentials Some credentials being added.
     * @return True only if the verification should be removed.
     */
    static boolean shouldBeRemoved(Verification verification, Iterable<Credential> credentials) {
      for (Credential c1 : credentials) {
        for (Credential c2 : verification.getCredentials()) {
          if (!c1.equals(c2) && c1.getClass().isInstance(c2)) {            
            return true;  // c1 will replace existing c2.
          }
        }
      }
      return false;
    }

    @Override
    public Set<Verification> get(AuthnSessionState.Summary summary, AuthnAuthority authority) {
      return summary.getVerifications(Predicates.equalTo(authority));
    }
  }

  public void testAddVerification() {
    CredentialGroup cg3, cg4;
    cg3 = CredentialGroup.builder("cg3", "cg3", true, true, false).
        addMechanism(mech11).addMechanism(mech12).build();
    cg4 = CredentialGroup.builder("cg4", "cg4", true, true, false).
        addMechanism(mech21).addMechanism(mech22).build();
    AuthnSessionState state = AuthnSessionState.empty();
    state = state.addVerification(mech21.getAuthority(), VERIFICATION2);
    state = state.addVerification(mech22.getAuthority(), VERIFICATION3);
    state = state.addVerification(mech11.getAuthority(), VERIFICATION1);
    state = state.addVerification(mech12.getAuthority(), VERIFICATION4);
    AuthnSessionState.Summary summary = state.computeSummary(
        ImmutableList.<CredentialGroup>of(cg3, cg4));
    assertEquals(3, summary.getVerificationsMap().size());
    assertEquals(6, summary.getCredentialsMap().size());
    assertNull(summary.getVerificationsMap().get(mech11.getAuthority()));
    assertEquals(VERIFICATION4, summary.getVerificationsMap().get(mech12.getAuthority()));
    assertEquals(VERIFICATION3, summary.getVerificationsMap().get(mech22.getAuthority()));
    assertEquals(VERIFICATION2, summary.getVerificationsMap().get(mech21.getAuthority()));
    Set<Credential> creds3 = summary.getCredentialsMap().get(cg3.getAuthority());
    Set<Credential> creds4 = summary.getCredentialsMap().get(cg4.getAuthority());
    for (Credential cred : creds3) {
      switch(cred.getTypeName()) {
        case PRINCIPAL:
          assertEquals(AuthnPrincipal.make("user4", "cg3"), cred);
          break;
        case PASSWORD:
          assertEquals(CredPassword.make("pass4"), cred);
          break;
        case GROUPS:
          assertEquals(GroupMemberships.make(ImmutableSet.of(Group.make("group1", "cg3"))), cred);
          break;
        default:
          // TODO(b/18683919): go/enum-switch-lsc
      }
    }
    for (Credential cred : creds4) {
      switch(cred.getTypeName()) {
        case PRINCIPAL:
          assertEquals(AuthnPrincipal.make("user4", "cg4"), cred);
          break;
        case PASSWORD:
          assertEquals(CredPassword.make("pass4"), cred);
          break;
        case GROUPS:
          assertEquals(GroupMemberships.make(ImmutableSet.of(Group.make("group1", "cg4"), 
              Group.make("group2", "cg4"), Group.make("group3", "cg4"))), cred);
          break;
        default:
          // TODO(b/18683919): go/enum-switch-lsc
      }
    } 
  }
  
  private <T> void runSingleTests(Tester<T> tester) {
    Gson gson = ConfigSingleton.getGson();
    List<TestInstruction<T>> instructions = enumerateInstructions(tester);
    for (List<TestInstruction<T>> instructions2 : Generators.permutationsOf(instructions)) {
      SetMultimap<AuthnAuthority, T> model = HashMultimap.create();
      tester.execute(instructions2, model);
      AuthnSessionState state = tester.execute(instructions2, AuthnSessionState.empty());
      tester.expect(model, state);
    }
    AuthnSessionState state
        = tester.execute(enumerateAddInstructions(tester), AuthnSessionState.empty());
    String jsonString = gson.toJson(state);
    AuthnSessionState newState = gson.fromJson(jsonString, AuthnSessionState.class);
    assertEquals(state, newState);    
  }

  private <T> List<TestInstruction<T>> enumerateInstructions(Tester<T> tester) {
    ImmutableList.Builder<TestInstruction<T>> builder = ImmutableList.builder();
    for (TestOperation operation : TestOperation.values()) {
      for (AuthnAuthority authority : AUTHORITIES) {
        for (T object : tester.getObjects()) {
          builder.add(new TestInstruction<T>(operation, authority, object));
        }
      }
    }
    return builder.build();
  }

  private <T> List<TestInstruction<T>> enumerateAddInstructions(Tester<T> tester) {
    ImmutableList.Builder<TestInstruction<T>> builder = ImmutableList.builder();
    for (AuthnAuthority authority : AUTHORITIES) {
      for (T object : tester.getObjects()) {
        builder.add(new TestInstruction<T>(TestOperation.ADD, authority, object));
      }
    }
    return builder.build();
  }
}
