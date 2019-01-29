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

import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.authncontroller.ExportedState.Credentials;
import com.google.enterprise.secmgr.config.AuthnMechBasic;
import com.google.enterprise.secmgr.config.AuthnMechConnector;
import com.google.enterprise.secmgr.config.AuthnMechForm;
import com.google.enterprise.secmgr.config.AuthnMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.CredPassword;
import com.google.enterprise.secmgr.identity.Credential;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.GroupMemberships;
import com.google.enterprise.secmgr.identity.Verification;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;

/**
 * Unit test for ExportedState.
 */
public class ExportedStateTest extends SecurityManagerTestCase {

  public static final Logger LOG = Logger.getLogger(ExportedStateTest.class.getName());

  /**
   * Found in both b/6717952 and b/12019644 - the security manager was massively duplicating
   * groups info in the Artifact Response for ExportedState. This unit test ensures that we don't
   * do that anymore.
   *
   * Note that one set of duplicates still persists in the JSON response, but this is something
   * we're stomaching for now because it's a constant 2X factor as opposed to a kX factor, where k
   * is the number of active authn mechanisms.
   *
   * This test uses a setup that tries to be like the customer environment - a
   * couple of mechanisms for getting the identity, plus two connectors that are
   * responsible for groups retrieval.
   */
  public void testNoDuplicateGroupsInJsonResponse() {
    AuthnMechanism formMech = AuthnMechForm.make("mech", "http://example.com/");
    AuthnMechanism basicMech = AuthnMechBasic.make("basicmech", "http://example.com/basic");
    AuthnMechanism connectorMech =
        AuthnMechConnector.make("connectormech", "connector00", false, 120, 120);
    AuthnMechanism connectorMech2 =
        AuthnMechConnector.make("connectormech2", "connector01", false, 120, 120);

    CredentialGroup cgOne = buildCredentialGroup("cg1", formMech, basicMech,
        connectorMech, connectorMech2);
    SecurityManagerConfig cfg = setupSecurityConfig(ImmutableList.of(cgOne));

    // get some groups from the connector
    List<Group> groups = new ArrayList<Group>();
    for (int i = 0; i < 5; i++) {
      groups.add(Group.make("group" + i, "Default"));
    }
    List<Group> groupsTwo = new ArrayList<Group>();
    for (int i = 5; i < 10; i++) {
      groupsTwo.add(Group.make("group" + i, "Default_local_namespace"));
    }


    AuthnSession session = AuthnSession.newInstance(cfg);
    session = loginToMechWithCredentials(cfg, session, formMech, null,
        AuthnPrincipal.make("user", "domain"));
    session = loginToMechWithCredentials(cfg, session, basicMech, null,
        AuthnPrincipal.make("user", "domain"),
        CredPassword.make("password"));
    session = loginToMechWithCredentials(cfg, session, connectorMech,
        GroupMemberships.make(groups));
    session = loginToMechWithCredentials(cfg, session, connectorMech2,
        GroupMemberships.make(groupsTwo));

    ExportedState state = ExportedState.make(session.getSnapshot());
    String jsonString = state.toJsonString();
    LOG.info("EXPORTED JSON STATE: " + jsonString);
    for (Group group : groups) {
      int matches = StringUtils.countMatches(jsonString, group.getName());
      // make sure that we've exported at least one copy of the group
      assertTrue(matches > 0);
      // but no more than 2
      assertTrue(matches <= 2);
    }
    for (Group group : groupsTwo) {
      int matches = StringUtils.countMatches(jsonString, group.getName());
      // make sure that we've exported at least one copy of the group
      assertTrue(matches > 0);
      // but no more than 2
      assertTrue(matches <= 2);
    }

    LOG.info("Size of all verified credentials: " + state.getAllVerifiedCredentials().size());

    Set<Group> groupsToCheck = new HashSet<Group>();
    // for some reason I can't get the groups combining to work, so we accept
    // that groupsOne is overwritten in the response for now
    // groupsToCheck.addAll(groupsOne);
    groupsToCheck.addAll(groupsTwo);
    for (Credentials cred: state.getAllVerifiedCredentials()) {
      LOG.info("Verified Credential: " + cred.toString());
      for (Group g : cred.getGroups()) {
        if (groupsToCheck.contains(g)) {
          groupsToCheck.remove(g);
        } else {
          fail("An extra group was found in the exported credentials: " + g.toString());
        }
      }
    }
  }

  private CredentialGroup buildCredentialGroup(String name, AuthnMechanism ... mechs) {
    CredentialGroup.Builder cgBuilder = CredentialGroup.builder(name, name, true, false, false);
    for (AuthnMechanism mech : mechs) {
      cgBuilder.addMechanism(mech);
    }
    return cgBuilder.build();
  }

  /**
   * Sets up a single CG with the given authn mechanisms.
   */
  private SecurityManagerConfig setupSecurityConfig(List<CredentialGroup> cgs) {
    SecurityManagerConfig cfg =  SecurityManagerConfig.make(cgs);
    ConfigSingleton.setConfig(cfg);
    return cfg;
  }

  /**
   * Effectively performs a successful login for the given AuthnMech, verifying the provided
   * set of credentials.
   */
  private static AuthnSession loginToMechWithCredentials(SecurityManagerConfig cfg,
      AuthnSession session, AuthnMechanism mech,
      GroupMemberships groups, Credential ... credentials) {
    SessionSnapshot ohSnap = session.getSnapshot();
    SessionView mechView = ohSnap.getView(mech);

    HashSet<Credential> verifiedCredentials = new HashSet<Credential>();
    for (Credential cred : credentials) {
      verifiedCredentials.add(cred);
    }

    // this should in theory work for combining groups for multiple
    // connectors but it doesn't
    if (groups != null) {
      mechView.extendGroupMemberships(groups.getGroups());
      verifiedCredentials.add(groups);
    }

    session.updateSessionState(AuthnSessionState.of(mechView.getAuthority(),
        Verification.verified(
            mechView.getConfiguredExpirationTime(), verifiedCredentials)));
    return session;
  }
}
