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

package com.google.enterprise.secmgr.common;

import junit.framework.TestCase;

public class IdentityUtilTest extends TestCase {
  private static final String USER = "foo";
  private static final String DOMAIN = "bar.com";
  private static final String USER_DOMAIN1 = "foo@bar.com";
  private static final String USER_DOMAIN2 = "bar.com\\foo";
  private static final String USER_DOMAIN3 = "bar.com/foo";
  
  public void testParseNameAndDomain() {
    String[] userDomain = IdentityUtil.parseNameAndDomain(USER_DOMAIN1);
    assertEquals(USER, userDomain[0]);
    assertEquals(DOMAIN, userDomain[1]);
    userDomain = IdentityUtil.parseNameAndDomain(USER_DOMAIN2);
    assertEquals(USER, userDomain[0]);
    assertEquals(DOMAIN, userDomain[1]);
    userDomain = IdentityUtil.parseNameAndDomain(USER_DOMAIN3);
    assertEquals(USER, userDomain[0]);
    assertEquals(DOMAIN, userDomain[1]);
  }
  
  public void testNormalizeDomain() {
    String domain = IdentityUtil.normalizeDomain("");
    assertEquals(null, domain);
    domain = IdentityUtil.normalizeDomain("foo.google.com");
    assertEquals("foo", domain);
    domain = IdentityUtil.normalizeDomain("google");
    assertEquals("google", domain);    
  }
}
