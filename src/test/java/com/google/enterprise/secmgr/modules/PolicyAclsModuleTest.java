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

package com.google.enterprise.secmgr.modules;

import static java.util.concurrent.TimeUnit.MILLISECONDS;

import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableList;
import com.google.common.io.Files;
import com.google.enterprise.policychecker.Acl;
import com.google.enterprise.policychecker.AclUtil;
import com.google.enterprise.policychecker.Authorizer;
import com.google.enterprise.policychecker.JsonUrlAclMapSerializer;
import com.google.enterprise.policychecker.PlainTextAclSerializer;
import com.google.enterprise.policychecker.Serializer;
import com.google.enterprise.policychecker.UrlAclMap;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.FileUtil;
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
import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.enterprise.supergsa.security.Domain;
import com.google.enterprise.supergsa.security.GsaAcl;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * Unit tests for {@link PolicyAclsModule}.
 */
public class PolicyAclsModuleTest extends SecurityManagerTestCase {

  private static final Logger LOG = Logger.getLogger(PolicyAclsModuleTest.class.getName());

  private static final String BOWL_URL = "http://bowling/strikes-and-gutters";
  private static final String GOLF_URL = "ftp://golfing/birdies-and-bogies";
  private static final String GOOD_GROUP_URL = "http://foo-bar-group";
  private static final String BOWLER = "ricky";
  private static final String GOLFER = "bobby";
  private static final String DOMAIN = "go-go-le.payasos";
  private static final String DUMBED_DOMAIN = "go-go-le";
  private static final ImmutableList<Group> BOWLER_GROUPS =
      ImmutableList.<Group>of(
          Group.make("foo", AuthorizationTestUtils.CG, DOMAIN),
          Group.make("bar", AuthorizationTestUtils.CG, DOMAIN));
  private static final ImmutableList<Group> GOLFER_GROUPS =
      ImmutableList.<Group>of(Group.make("baz", "cg", DOMAIN));


  public void testAcl()
      throws IOException {
    List<String> urls = Arrays.asList(BOWL_URL, GOLF_URL, GOOD_GROUP_URL);
    SessionView view = AuthorizationTestUtils.simpleView(
        AuthnPrincipal.make(BOWLER, AuthorizationTestUtils.CG, DOMAIN),
        GroupMemberships.make(BOWLER_GROUPS));
    PolicyAclsModule policyAclModule = new PolicyAclsModule(new MockAuthorizer());
    AuthzResult decisions = policyAclModule.authorize(
        Resource.urlsToResourcesNoAcls(urls), view, AuthorizationTestUtils.DUMMY_RULE);
    assertEquals(3, decisions.size());
    assertEquals(AuthzStatus.PERMIT, decisions.get(BOWL_URL));
    assertEquals(AuthzStatus.DENY, decisions.get(GOLF_URL));
    assertEquals(AuthzStatus.PERMIT, decisions.get(GOOD_GROUP_URL));
  }

  public void testAcl2()
      throws IOException {
    List<String> urls = Arrays.asList(BOWL_URL, GOLF_URL, GOOD_GROUP_URL);
    SessionView view = AuthorizationTestUtils.simpleView(
        AuthnPrincipal.make(GOLFER, AuthorizationTestUtils.CG, DOMAIN),
        GroupMemberships.make(GOLFER_GROUPS));
    PolicyAclsModule policyAclModule = new PolicyAclsModule(new MockAuthorizer());
    AuthzResult decisions = policyAclModule.authorize(
        Resource.urlsToResourcesNoAcls(urls), view, AuthorizationTestUtils.DUMMY_RULE);
    assertEquals(3, decisions.size());
    assertEquals(AuthzStatus.DENY, decisions.get(BOWL_URL));
    assertEquals(AuthzStatus.PERMIT, decisions.get(GOLF_URL));
    assertEquals(AuthzStatus.DENY, decisions.get(GOOD_GROUP_URL));
  }

  public void testLateBinding() throws IOException {
    SecurityManagerConfig config = ConfigSingleton.getConfig();
    ConfigParams.Builder builder = ConfigParams.builder(config.getParams());
    builder.put(ParamName.LATE_BINDING_ACL, true);
    config.setParams(builder.build());
    List<String> urls = Arrays.asList(BOWL_URL, GOLF_URL, GOOD_GROUP_URL);
    SessionView view = AuthorizationTestUtils.simpleView(
        AuthnPrincipal.make(GOLFER, AuthorizationTestUtils.CG, DOMAIN),
        GroupMemberships.make(GOLFER_GROUPS));
    PolicyAclsModule policyAclModule = new PolicyAclsModule(new MockAuthorizer());
    AuthzResult decisions = policyAclModule.authorize(
        Resource.urlsToResourcesNoAcls(urls), view, AuthorizationTestUtils.DUMMY_RULE);
    assertEquals(3, decisions.size());
    assertEquals(AuthzStatus.DENY, decisions.get(BOWL_URL));
    assertEquals(AuthzStatus.INDETERMINATE, decisions.get(GOLF_URL));
    assertEquals(AuthzStatus.DENY, decisions.get(GOOD_GROUP_URL));
  }

  private static class MockAuthorizer implements Authorizer {

    MockAuthorizer() {
    }

    public Acl get(String url) {
      Serializer<Acl> serializer = new PlainTextAclSerializer();
      if (BOWL_URL.equals(url)) {
        return getAcl(BOWLER, AclPrincipal.SCOPE.USER);
      } else if (GOLF_URL.equals(url)) {
        return getAcl(GOLFER, AclPrincipal.SCOPE.USER);
      } else if (GOOD_GROUP_URL.equals(url)) {
        return getAcl("foo", AclPrincipal.SCOPE.GROUP);
      }
      throw new IllegalStateException();
    }

    public boolean canRead(String name, String url) {
      throw new UnsupportedOperationException();
    }

    private Acl getAcl(String name, AclPrincipal.SCOPE scope) {
      AclPrincipal aclP = AclPrincipal.newBuilder()
          .setScope(scope)
      .setCaseSensitive(AclPrincipal.CaseSensitivity.EVERYTHING_CASE_SENSITIVE)
      .setName(name)
      .setNameSpace(AuthorizationTestUtils.CG)
      .setDomain(Domain.newBuilder()
          .setName(DUMBED_DOMAIN)
          .setType(Domain.DomainType.NETBIOS)
          .build())
      .build();

      GsaAcl.Builder acl = GsaAcl.newBuilder();
      AclUtil.addGsaEntry(acl, aclP);
      return Acl.fromGsaAcl(acl.build());
    }
  }

  public void testMissingVerifiedPrincipal() throws IOException {
    List<String> urls = Arrays.asList(BOWL_URL, GOLF_URL);
    SessionView withoutVP = AuthorizationTestUtils.simpleView();
    PolicyAclsModule decider = new PolicyAclsModule(new MockAuthorizer());
    AuthzResult decisions = decider.authorize(
        Resource.urlsToResourcesNoAcls(urls), withoutVP, AuthorizationTestUtils.DUMMY_RULE);
    assertEquals(2, decisions.size());
    assertEquals(AuthzStatus.INDETERMINATE, decisions.get(BOWL_URL));
    assertEquals(AuthzStatus.INDETERMINATE, decisions.get(GOLF_URL));
  }

  public void testDataReloading() throws Exception {
    String urlsFilename = FileUtil.getContextDirectory()
        + "/" + "acl_urls.enterprise";
    String urls2Filename = FileUtil.getContextDirectory()
        + "/" + "acl_urls_2.enterprise";

    // The following commented code are purposely left here for reference.
    // It takes time to generate files. So pre-generated for speedy testing.
    /*
    generateAclsFile(urlsFilename);
    generateAclsFile(urls2Filename);
    */
    runAuthorize(urlsFilename, urls2Filename, 1000);
  }

  public void testLoadLargeFiles() throws Exception {
    String urlsFilename = FileUtil.getContextDirectory()
        + "/" + "acl_urls_large.enterprise";
    String urls2Filename = FileUtil.getContextDirectory()
        + "/" + "acl_urls_2_large.enterprise";
    runAuthorize(urlsFilename, urls2Filename, 100000);
  }

  private void runAuthorize(String urlsFilename, String urls2Filename,
      long waitForFileRead)
      throws Exception {
    final long fileTimestampPrecisionMillis = 1000;
    final long checkForNewFileMillis = 12;

    // Duplicate original rules in writable tmp file.
    File dupOfOriginalRules = File.createTempFile("acl_urls_", ".enterprise");
    dupOfOriginalRules.deleteOnExit();
    dupOfOriginalRules.setWritable(true);
    Files.copy(new File(urlsFilename), dupOfOriginalRules);

    Stopwatch watch = Stopwatch.createStarted();
    PolicyAclsModule decider = new PolicyAclsModule(
        dupOfOriginalRules.getAbsolutePath(), checkForNewFileMillis);
    watch.stop();
    LOG.info("Took " + watch.elapsed(MILLISECONDS) + " ms to load the module");

    List<String> urls = Arrays.asList(BOWL_URL, GOLF_URL);
    AuthzResult decisions;
    // Names (golfer and bowler) are from data files.
    SessionView golfer = AuthorizationTestUtils.simpleView(AuthnPrincipal.make("golfer",
        AclUtil.DEFAULT_NAMESPACE));
    SessionView bowler = AuthorizationTestUtils.simpleView(AuthnPrincipal.make("bowler",
        AclUtil.DEFAULT_NAMESPACE));

    // Check initially loaded data.
    watch.reset();
    watch.start();
    decisions = decider.authorize(
        Resource.urlsToResourcesNoAcls(urls), golfer, AuthorizationTestUtils.DUMMY_RULE);
    watch.stop();
    LOG.info("Took " + watch.elapsed(MILLISECONDS) + " ms to authorize");
    assertEquals(2, decisions.size());
    assertEquals(AuthzStatus.DENY, decisions.get(BOWL_URL));
    assertEquals(AuthzStatus.PERMIT, decisions.get(GOLF_URL));

    // Still checking initial data.
    decisions = decider.authorize(
        Resource.urlsToResourcesNoAcls(urls), bowler, AuthorizationTestUtils.DUMMY_RULE);
    assertEquals(2, decisions.size());
    assertEquals(AuthzStatus.PERMIT, decisions.get(BOWL_URL));
    assertEquals(AuthzStatus.DENY, decisions.get(GOLF_URL));

    Thread.sleep(fileTimestampPrecisionMillis);
    Files.write(Files.toByteArray(new File(urls2Filename)), dupOfOriginalRules);
    Thread.sleep(waitForFileRead);  // Give enough time for re-read to complete.

    // Check newly loaded data.
    watch.reset();
    watch.start();
    decisions = decider.authorize(
        Resource.urlsToResourcesNoAcls(urls), golfer, AuthorizationTestUtils.DUMMY_RULE);
    watch.stop();
    LOG.info("Took " + watch.elapsed(MILLISECONDS) + " ms to authorize");
    assertEquals(2, decisions.size());
    assertEquals(AuthzStatus.PERMIT, decisions.get(BOWL_URL));
    assertEquals(AuthzStatus.DENY, decisions.get(GOLF_URL));

    decisions = decider.authorize(
        Resource.urlsToResourcesNoAcls(urls), bowler, AuthorizationTestUtils.DUMMY_RULE);
    assertEquals(2, decisions.size());
    assertEquals(AuthzStatus.DENY, decisions.get(BOWL_URL));
    assertEquals(AuthzStatus.PERMIT, decisions.get(GOLF_URL));
  }

  // Generate large acls files.
  private void generateAclsFile(String filename) throws Exception {
    JsonUrlAclMapSerializer serializer = new JsonUrlAclMapSerializer();
    UrlAclMap urlAclMap = serializer.parseFromFile(filename);

    // Add more data
    String testUrlPrefix = "http://test.com/";

    for (int i = 0; i < 5000; i++) {
      AclPrincipal group = AclUtil.groupToAclPrincipal("group" + i);
      AclPrincipal user = AclUtil.userNameToAclPrincipal("user" + i);

      GsaAcl.Builder acl = GsaAcl.newBuilder();
      AclUtil.addGsaEntry(acl, group);
      AclUtil.addGsaEntry(acl, user);
      urlAclMap.addPattern(testUrlPrefix + i, Acl.fromGsaAcl(acl.build()));
    }

    File tmpFile = File.createTempFile(getClass().getName() + "-acl", ".tmp");
    // ../testdata/acl_urls_large.enterprise is copied from the file generated this way.
    // This sometimes take about 74409 ms to load at this writing.
    // For 10k entries of acl and 1k entries of groups, takes about 190sec
    LOG.info("acl " + tmpFile.toString());
    serializer.writeToFile(urlAclMap, tmpFile.getCanonicalPath());
  }
}
