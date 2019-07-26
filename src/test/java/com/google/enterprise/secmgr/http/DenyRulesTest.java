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

package com.google.enterprise.secmgr.http;

import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

/**
 * Tests for the {@link DenyRules} class.
 *
 */
public class DenyRulesTest extends SecurityManagerTestCase {
  private DenyRules denyRules;

  @Override
  protected void setUp() throws Exception {
    super.setUp();
    denyRules = new DenyRules();
    denyRules.setConfFile(
        "deny_rules.enterprise");
  }

  public void testGetRule() throws Exception {
    DenyRule denyRule = denyRules.getRule("http://www.teststatus.com/");
    assertNotNull(denyRule);
    assertTrue(denyRule.getStatusCodeList().contains(402));

    denyRule = denyRules.getRule("http://www.testcontent.com/");
    assertNotNull(denyRule);
    assertTrue(denyRule.getContentList().contains("forbidden"));

    denyRule = denyRules.getRule("http://localhost/");
    assertNotNull(denyRule);
    assertTrue(denyRule.getContentList().contains("denyphrase"));
    assertTrue(denyRule.getStatusCodeList().contains(302));

    denyRule = denyRules.getRule("http://localhost:1234/");
    assertNotNull(denyRule);

    denyRule = denyRules.getRule("http://localhost:2345/");
    assertNotNull(denyRule);

    denyRule = denyRules.getRule("http://notcovered.com/");
    assertNull(denyRule);
  }
}
