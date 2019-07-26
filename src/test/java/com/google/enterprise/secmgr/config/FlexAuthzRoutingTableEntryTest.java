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

package com.google.enterprise.secmgr.config;

import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

public class FlexAuthzRoutingTableEntryTest extends SecurityManagerTestCase {
  private static boolean isValidPattern(String pat) {
    return FlexAuthzRoutingTableEntry.isValidPattern(pat);
  }
  public void testPatternValidation() {
    assertTrue("Http prefix rejected.", isValidPattern("http://"));
    assertTrue("Postfix rejected.", isValidPattern("jpg$"));
    assertTrue("Whitespace rejected.", isValidPattern(" "));
    assertFalse("Empty string accepted.", isValidPattern(""));
    assertFalse("Beginning hyphen accepted.", isValidPattern("-19%"));
    assertFalse("www?: accepted.", isValidPattern("www?:"));
    assertFalse("Faulty regexp accepted.", isValidPattern("regexp:*.pdf"));
    assertFalse("Faulty regexp accepted.", isValidPattern("regexpIgnoreCase:*.pdf"));
    assertFalse("Faulty regexp accepted.", isValidPattern("regexpCase:*.pdf"));
    assertTrue("Contains rejected", isValidPattern("contains:*.pdf"));
  }
}
