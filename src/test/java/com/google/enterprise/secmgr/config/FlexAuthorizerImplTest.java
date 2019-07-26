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

package com.google.enterprise.secmgr.config;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.enterprise.secmgr.config.FlexAuthzRule.ParamName;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.Test;

public class FlexAuthorizerImplTest extends SecurityManagerTestCase {
  private static FlexAuthorizer flexAuthz;
  private static Map<ParamName, String> mechSpecificParams;
  private static FlexAuthzRule authzRule1, authzRule2;
  private static FlexAuthzRoutingTableEntry routingTableEntry1, routingTableEntry2;

  @Override
  public void setUp()
      throws Exception {
    super.setUp();
    flexAuthz = ConfigSingleton.getInstance(FlexAuthorizer.class);
    mechSpecificParams
        = ImmutableMap.of(
            ParamName.SAML_ENTITY_ID, "dummy_entity_id",
            ParamName.SAML_USE_BATCHED_REQUESTS, "false");
    authzRule1 = new FlexAuthzRule("authnId1", AuthzMechanism.SAML,
        mechSpecificParams, "rule1", 1000);
    authzRule2 = new FlexAuthzRule("authnId2", AuthzMechanism.SAML,
        mechSpecificParams, "rule2", 1000);
    routingTableEntry1 = new FlexAuthzRoutingTableEntry("pattern1", authzRule1);
    routingTableEntry2 = new FlexAuthzRoutingTableEntry("pattern2", authzRule2);
    addTearDown(new TearDown() {
      @Override
      public void tearDown() throws Exception {
        flexAuthz.clearTables();
      }
    });
  }

  @Test
  public final void testAddToRoutingTable() {

    flexAuthz.addToRulesTable(authzRule1);

    // Adding a valid entry.
    flexAuthz.addToRoutingTable(0, routingTableEntry1);
    assertEquals("pattern1", flexAuthz.getAllRoutingTable().get(0).getUrlPattern());
    assertEquals("rule1", flexAuthz.getAllRoutingTable().get(0).getAuthzRule().getRowDisplayName());
    assertEquals(1, flexAuthz.getAllRoutingTable().size());

    // Adding an entry whose corresponding authz rule does not exist.
    boolean exceptionCaught = false;
    try {
      flexAuthz.addToRoutingTable(0, routingTableEntry2);
    } catch (IllegalArgumentException e) {
      exceptionCaught = true;
    }
    assertTrue(exceptionCaught);

    // Adding an invalid order.
    exceptionCaught = false;
    flexAuthz.addToRulesTable(authzRule2);
    try {
      flexAuthz.addToRoutingTable(3, routingTableEntry2);
    } catch (IllegalArgumentException e) {
      exceptionCaught = true;
    }
    assertTrue(exceptionCaught);
  }

  @Test
  public final void testAddToRulesTable() {
    // Adding a valid entry.
    flexAuthz.addToRulesTable(authzRule1);

    // Adding a duplicate rule.
    boolean exceptionCaught = false;
    authzRule2 = new FlexAuthzRule("authnId2", AuthzMechanism.SAML,
        mechSpecificParams, "rule1", 1000);
    try {
      flexAuthz.addToRulesTable(authzRule1);
    } catch (IllegalArgumentException e) {
      exceptionCaught = true;
    }
    assertTrue(exceptionCaught);
    assertEquals(1, flexAuthz.getAllRulesTable().size());
  }

  @Test
  public final void testClearTables() {
    flexAuthz.addToRulesTable(authzRule1);
    flexAuthz.addToRulesTable(authzRule2);
    flexAuthz.addToRoutingTable(0, routingTableEntry1);
    flexAuthz.addToRoutingTable(1, routingTableEntry2);
    assertEquals(2, flexAuthz.getAllRoutingTable().size());
    assertEquals(2, flexAuthz.getAllRulesTable().size());

    flexAuthz.clearTables();
    assertEquals(0, flexAuthz.getAllRoutingTable().size());
    assertEquals(0, flexAuthz.getAllRulesTable().size());

  }

  @Test
  public final void testDeleteFromRoutingTable() {
    flexAuthz.addToRulesTable(authzRule1);
    flexAuthz.addToRulesTable(authzRule2);
    flexAuthz.addToRoutingTable(0, routingTableEntry1);
    flexAuthz.addToRoutingTable(1, routingTableEntry2);
    assertEquals(2, flexAuthz.getAllRoutingTable().size());

    flexAuthz.deleteFromRoutingTable(routingTableEntry1.getUniqueRowId());
    assertEquals(1, flexAuthz.getAllRoutingTable().size());
  }

  @Test
  public final void testDeleteFromRulesTable() {
    boolean caughtException = false;
    // Remove rule when it is not associated to the routing table.
    flexAuthz.addToRulesTable(authzRule1);
    flexAuthz.addToRulesTable(authzRule2);
    assertEquals(2, flexAuthz.getAllRulesTable().size());
    flexAuthz.deleteFromRulesTable(authzRule1.getRowDisplayName());
    assertEquals(1, flexAuthz.getAllRulesTable().size());

    // Delete rule which has association in the routing table.
    flexAuthz.addToRoutingTable(0, routingTableEntry2);
    try {
      flexAuthz.deleteFromRulesTable(authzRule2.getRowDisplayName());
    } catch (IllegalStateException e) {
      caughtException = true;
    }
    assertTrue(caughtException);
    assertEquals(1, flexAuthz.getAllRulesTable().size());
  }

  @Test
  public final void testGetAllRoutingTable() {
    flexAuthz.addToRulesTable(authzRule1);
    flexAuthz.addToRulesTable(authzRule2);
    flexAuthz.addToRoutingTable(0, routingTableEntry1);
    flexAuthz.addToRoutingTable(1, routingTableEntry2);
    List<FlexAuthzRoutingTableEntry> entries = flexAuthz.getAllRoutingTable();
    assertEquals(2, entries.size());
  }

  @Test
  public final void testGetAllRulesTable() {
    flexAuthz.addToRulesTable(authzRule1);
    flexAuthz.addToRulesTable(authzRule2);
    List<FlexAuthzRule> entries = flexAuthz.getAllRulesTable();
    assertEquals(2, entries.size());
  }

  @Test
  public final void testGetFromRoutingTable() {
    flexAuthz.addToRulesTable(authzRule1);
    flexAuthz.addToRulesTable(authzRule2);
    flexAuthz.addToRoutingTable(0, routingTableEntry1);
    flexAuthz.addToRoutingTable(1, routingTableEntry2);
    FlexAuthzRoutingTableEntry entry =
        flexAuthz.getFromRoutingTable(routingTableEntry2.getUniqueRowId());
    assertEquals("pattern2", entry.getUrlPattern());
    assertEquals("rule2", entry.getAuthzRule().getRowDisplayName());
  }

  @Test
  public final void testGetFromRulesTable() {
    flexAuthz.addToRulesTable(authzRule1);
    flexAuthz.addToRulesTable(authzRule2);
    FlexAuthzRule entry =  flexAuthz.getFromRulesTable("rule2");
    assertEquals("rule2", entry.getRowDisplayName());
  }

  @Test
  public final void testUpdateRoutingTable() {
    flexAuthz.addToRulesTable(authzRule1);
    flexAuthz.addToRulesTable(authzRule2);
    flexAuthz.addToRoutingTable(0, routingTableEntry1);
    flexAuthz.addToRoutingTable(1, routingTableEntry2);

    // Update valid entry with different order.
    FlexAuthzRoutingTableEntry newEntry = new FlexAuthzRoutingTableEntry(
        "pattern3", authzRule2, routingTableEntry1.getUniqueRowId());
    flexAuthz.updateRoutingTable(1, newEntry);
    assertEquals(authzRule2.getRowDisplayName(), flexAuthz.getFromRoutingTable(
        routingTableEntry1.getUniqueRowId()).getAuthzRule().getRowDisplayName());
    assertEquals("pattern2", flexAuthz.getAllRoutingTable().get(0).getUrlPattern());
    assertEquals("pattern3", flexAuthz.getAllRoutingTable().get(1).getUrlPattern());

    // Update valid entry with same order.
    newEntry = new FlexAuthzRoutingTableEntry(
        "pattern4", authzRule2, routingTableEntry1.getUniqueRowId());
    flexAuthz.updateRoutingTable(1, newEntry);
    assertEquals("pattern2", flexAuthz.getAllRoutingTable().get(0).getUrlPattern());
    assertEquals("pattern4", flexAuthz.getAllRoutingTable().get(1).getUrlPattern());

    // Only change the order.
    flexAuthz.updateRoutingTable(0, newEntry);
    assertEquals("pattern4", flexAuthz.getAllRoutingTable().get(0).getUrlPattern());
    assertEquals("pattern2", flexAuthz.getAllRoutingTable().get(1).getUrlPattern());

    // Update entry with wrong order.
    try {
      flexAuthz.updateRoutingTable(2, newEntry);
      fail();
    } catch (IllegalArgumentException e) {
      // pass
    }

    // Update entry with no associated rule in ruleTable.
    FlexAuthzRule authzRule3 = new FlexAuthzRule("authnId3", AuthzMechanism.SAML,
        mechSpecificParams, "rule3", 1000);
    newEntry = new FlexAuthzRoutingTableEntry(
        "pattern3", authzRule3, routingTableEntry1.getUniqueRowId());
    try {
      flexAuthz.updateRoutingTable(1, newEntry);
      fail();
    } catch (IllegalArgumentException e) {
      // pass
    }
  }

  @Test
  public final void testUpdateRulesTable() {
    flexAuthz.addToRulesTable(authzRule1);
    flexAuthz.addToRulesTable(authzRule2);

    flexAuthz.addToRoutingTable(routingTableEntry1);
    flexAuthz.addToRoutingTable(routingTableEntry2);

    // Updating valid entry
    FlexAuthzRule authzRule3 = new FlexAuthzRule("authnId3", AuthzMechanism.SAML,
        mechSpecificParams, "rule1", 1000);
    try {
      flexAuthz.updateRulesTable(authzRule3);
    } catch (IllegalArgumentException e) {
      fail();
    }

    // Updating an invalid entry
    authzRule3 = new FlexAuthzRule("authnId3", AuthzMechanism.SAML,
        mechSpecificParams, "rule3", 1000);
    try {
      flexAuthz.updateRulesTable(authzRule3);
      fail();
    } catch (IllegalArgumentException e) {
      // pass
    }
  }

  @Test
  public final void testHashCodeAndEquals() {
    FlexAuthorizerImpl flexAuthorizer1 = new FlexAuthorizerImpl(
        ImmutableMap.of("rule1", authzRule1), ImmutableList.of(routingTableEntry1));
    FlexAuthorizerImpl flexAuthorizer2 = new FlexAuthorizerImpl(
        ImmutableMap.of("rule1", authzRule1), ImmutableList.of(routingTableEntry1));
    FlexAuthorizerImpl flexAuthorizer3 = new FlexAuthorizerImpl(
        ImmutableMap.of("rule3", authzRule1), ImmutableList.of(routingTableEntry1));
    assertEquals(flexAuthorizer1.hashCode(), flexAuthorizer2.hashCode());
    assertEquals(flexAuthorizer1, flexAuthorizer2);
    assertTrue(flexAuthorizer1 != flexAuthorizer3);
  }

  @Test
  public final void testAuthzRuleHashCodeAndEquals() {
    FlexAuthzRule ar1 = new FlexAuthzRule("authnId1", AuthzMechanism.SAML,
        mechSpecificParams, "rule1", 1000);
    FlexAuthzRule ar2 = new FlexAuthzRule("authnId1", AuthzMechanism.SAML,
        mechSpecificParams, "rule1", 1000);
    FlexAuthzRule ar3 = new FlexAuthzRule("authnId3", AuthzMechanism.SAML,
        mechSpecificParams, "rule3", 1000);
    assertEquals(ar1.hashCode(), ar2.hashCode());
    assertEquals(ar1, ar2);
    assertTrue(ar1 != ar3);
  }

  @Test
  public final void testRoutingEntryHashCodeAndEquals() {
    UUID uuid = UUID.randomUUID();
    FlexAuthzRoutingTableEntry re1 = new FlexAuthzRoutingTableEntry("pattern1", authzRule1, uuid);
    FlexAuthzRoutingTableEntry re2 = new FlexAuthzRoutingTableEntry("pattern1", authzRule1, uuid);
    FlexAuthzRoutingTableEntry re3 = new FlexAuthzRoutingTableEntry("pattern3", authzRule1, uuid);
    assertEquals(re1.hashCode(), re2.hashCode());
    assertEquals(re1, re2);
    assertTrue(re1 != re3);
  }
}
