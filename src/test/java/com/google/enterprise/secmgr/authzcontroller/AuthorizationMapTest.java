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

package com.google.enterprise.secmgr.authzcontroller;

import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.ALLOW_ALL;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.ALLOW_ALL_METHOD;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.ALLOW_BY_SUBSTRING;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.ALLOW_BY_SUBSTRING_METHOD;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.ALLOW_NONE;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.ALLOW_NONE_METHOD;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.BAR;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.FOO;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SI_BAR;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SI_FOO;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SI_XYZZY;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SO_BAR;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SO_FOO;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.SO_XYZZY;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.UNKNOWN;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.XYZZY;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.addStandardAuthorizationRules;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.assertComparableCollectionsEqual;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.getResourceFunc;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.makeQuery;
import static com.google.enterprise.secmgr.testing.AuthorizationTestUtils.standardPattern;

import com.google.common.collect.Collections2;
import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

import java.util.Collection;
import java.util.List;

/**
 * Unit tests for {@link AuthorizationMap}.
 */
public class AuthorizationMapTest extends SecurityManagerTestCase {

  public void testMapResources() {
    // set up a simple AuthorizationMap -- such as a simple CM might use
    AuthorizationMap.Builder builder = AuthorizationMap.builder();
    addStandardAuthorizationRules(builder);
    AuthorizationMap map = builder.build();
    List<AuthorizationQuery> expected
        = ImmutableList.of(
            makeQuery(standardPattern(ALLOW_ALL, SI_BAR), ALLOW_ALL_METHOD),
            makeQuery(standardPattern(ALLOW_ALL, SI_FOO), ALLOW_ALL_METHOD),
            makeQuery(standardPattern(ALLOW_ALL, SI_XYZZY), ALLOW_ALL_METHOD),
            makeQuery(standardPattern(ALLOW_NONE, SI_BAR), ALLOW_NONE_METHOD),
            makeQuery(standardPattern(ALLOW_NONE, SI_FOO), ALLOW_NONE_METHOD),
            makeQuery(standardPattern(ALLOW_NONE, SI_XYZZY), ALLOW_NONE_METHOD),
            makeQuery(standardPattern(ALLOW_BY_SUBSTRING, SI_FOO), ALLOW_BY_SUBSTRING_METHOD),
            makeQuery(standardPattern(ALLOW_BY_SUBSTRING, SI_BAR), ALLOW_BY_SUBSTRING_METHOD),
            makeQuery(standardPattern(ALLOW_BY_SUBSTRING, SI_XYZZY), ALLOW_BY_SUBSTRING_METHOD),
            makeQuery(standardPattern(ALLOW_ALL, BAR), ALLOW_ALL_METHOD),
            makeQuery(standardPattern(ALLOW_ALL, FOO), ALLOW_ALL_METHOD),
            makeQuery(standardPattern(ALLOW_ALL, XYZZY), ALLOW_ALL_METHOD),
            makeQuery(standardPattern(ALLOW_NONE, SO_BAR), ALLOW_NONE_METHOD),
            makeQuery(standardPattern(ALLOW_NONE, SO_FOO), ALLOW_NONE_METHOD),
            makeQuery(standardPattern(ALLOW_NONE, SO_XYZZY), ALLOW_NONE_METHOD),
            makeQuery(standardPattern(ALLOW_BY_SUBSTRING, FOO), ALLOW_BY_SUBSTRING_METHOD),
            makeQuery(standardPattern(ALLOW_BY_SUBSTRING, SO_BAR), ALLOW_BY_SUBSTRING_METHOD),
            makeQuery(standardPattern(ALLOW_BY_SUBSTRING, SO_XYZZY), ALLOW_BY_SUBSTRING_METHOD),
            makeQuery(standardPattern(UNKNOWN, SO_XYZZY)));
    // create queries
    Collection<Resource> resources = Collections2.transform(expected, getResourceFunc);
    Collection<AuthorizationQuery> actual = map.mapResources(resources);
    assertComparableCollectionsEqual(expected, actual);
  }
}
