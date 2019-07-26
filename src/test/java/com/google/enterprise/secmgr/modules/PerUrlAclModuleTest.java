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

package com.google.enterprise.secmgr.modules;

import com.google.common.collect.ImmutableList;
import com.google.enterprise.policychecker.Acl;
import com.google.enterprise.policychecker.AclUtil;
import com.google.enterprise.policychecker.PlainTextAclSerializer;
import com.google.enterprise.policychecker.Serializer;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.ConfigParams;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.ParamName;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.identity.AuthnPrincipal;
import com.google.enterprise.secmgr.identity.Group;
import com.google.enterprise.secmgr.identity.GroupMemberships;
import com.google.enterprise.secmgr.testing.AuthorizationTestUtils;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import java.util.Collection;
import java.util.logging.Logger;

/**
 * Unit tests for @link PerUrlAclModule
 *
 */
public class PerUrlAclModuleTest extends SecurityManagerTestCase {
  private static final Logger logger = Logger.getLogger(PerUrlAclModuleTest.class.getName());
  private static final String URL9 = "http://foo.com/";
  private static final String URL10 = "http://bar.com/";
  private static final String URL11 = "http://baz.com/";
  private static final String GOOD_USER = "ruth";
  private static final ImmutableList<Group> GOOD_GROUPS =
      ImmutableList.<Group>of(
          Group.make("qa", AclUtil.DEFAULT_NAMESPACE), Group.make("hr", AclUtil.DEFAULT_NAMESPACE));
  private static final String DOMAIN = "go-go-le.payasos";
  private Resource resource9, resource10, resource11, resource12;
  private Collection<Resource> resources;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    Serializer<Acl> serializer = new PlainTextAclSerializer();
    resource9 = new Resource(URL9, AuthzStatus.DENY);
    resource10 = new Resource(URL10, AuthzStatus.PERMIT);
    resource11 = new Resource(URL11, AuthzStatus.INDETERMINATE);
    ImmutableList.Builder<Resource> resourceBuilder = ImmutableList.builder();
    resourceBuilder.add(resource9);
    resourceBuilder.add(resource10);
    resourceBuilder.add(resource11);
    resources = resourceBuilder.build();
  }

  public void testAuthorize() {
    PerUrlAclModule perUrlAclMod = new PerUrlAclModule();
    SessionView view = AuthorizationTestUtils.simpleView(
        AuthnPrincipal.make(GOOD_USER, AclUtil.DEFAULT_NAMESPACE), 
                            GroupMemberships.make(GOOD_GROUPS));
    AuthzResult decisions
        = perUrlAclMod.authorize(resources, view,  AuthorizationTestUtils.DUMMY_RULE);
    assertEquals(3, decisions.size());
    assertEquals(AuthzStatus.DENY, decisions.get(URL9));
    assertEquals(AuthzStatus.PERMIT, decisions.get(URL10));
    assertEquals(AuthzStatus.INDETERMINATE, decisions.get(URL11));
  }

  public void testLateBinding() throws IOException {
    SecurityManagerConfig config = ConfigSingleton.getConfig();
    ConfigParams.Builder builder = ConfigParams.builder(config.getParams());
    builder.put(ParamName.LATE_BINDING_ACL, true);
    config.setParams(builder.build());
    logger.info(config.getParams().get(ParamName.LATE_BINDING_ACL).toString());
    PerUrlAclModule perUrlAclMod = new PerUrlAclModule();
    SessionView view = AuthorizationTestUtils.simpleView(
        AuthnPrincipal.make(GOOD_USER, AclUtil.DEFAULT_NAMESPACE), 
        GroupMemberships.make(GOOD_GROUPS));
    AuthzResult decisions
        = perUrlAclMod.authorize(resources, view,  AuthorizationTestUtils.DUMMY_RULE);
    assertEquals(3, decisions.size());
    assertEquals(AuthzStatus.DENY, decisions.get(URL9));
    assertEquals(AuthzStatus.INDETERMINATE, decisions.get(URL10));
    assertEquals(AuthzStatus.INDETERMINATE, decisions.get(URL11));
  }
}
