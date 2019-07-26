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

package com.google.enterprise.secmgr.saml;

import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import com.google.enterprise.util.C;
import java.io.File;
import java.util.logging.Logger;
import javax.xml.namespace.QName;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.w3c.dom.Document;

/**
 * Unit tests for the {@link Metadata} class.
 */
public class MetadataTest extends SecurityManagerTestCase {
  private static final Logger logger = Logger.getLogger(MetadataTest.class.getName());
  private static final String TEMP_SAML_METADATA_NAME = "tempSamlMetadata.xml";
  private static final String HOST1 = "myhost.com";
  private static final String CLIENT_ENTITY_ID = "myClientEntity";
  private static final String CLIENT_URL = "https://client.example.com/samlLogin";
  private static final String CLIENT_ARTIFACT_URL =
      "https://client.example.com/samlArtifactResolver";
  private static final String CLIENT_CERTIFICATE = null;

  private File tempSamlMetadata;

  @Override
  public void setUp()
      throws Exception {
    super.setUp();
    tempSamlMetadata = FileUtil.getCommonFile(TEMP_SAML_METADATA_NAME);
    MetadataEditor.writeMetadataDocument(
        MetadataEditor.makeOnboardSecurityManagerMetadata(),
        tempSamlMetadata);
    Metadata.setMetadataFile(tempSamlMetadata);
  }

  public void testBasic()
      throws Exception {
    Metadata metadata = Metadata.getInstanceForTest(HOST1);
    assertEquals(C.entityIdForSecMgr(SecurityManagerTestCase.GSA_TESTING_ISSUER),
        Metadata.getSmEntityId());
    assertNull(findClientsDescriptor(metadata));
    try {
      metadata.getEntity(CLIENT_ENTITY_ID);
      fail("Expected entity to be absent: " + CLIENT_ENTITY_ID);
    } catch (IllegalArgumentException e) {
      // pass
    }
  }

  public void testQuotation()
      throws Exception {
    EntityDescriptor entity = Metadata.getInstanceForTest(HOST1).getSmEntity();
    assertNotNull(entity);
    IDPSSODescriptor descriptor = entity.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    assertNotNull(descriptor);
    Endpoint endpoint = descriptor.getSingleSignOnServices().get(0);
    assertNotNull(endpoint);
    assertEquals(SAMLConstants.SAML2_REDIRECT_BINDING_URI, endpoint.getBinding());
    assertEquals("http://" + HOST1 + "/security-manager/samlauthn", endpoint.getLocation());
  }

  public void testRefresh()
      throws Exception {
    logMetadataModified();
    // Make sure that enough time has passed so that the mod time on the file
    // will be different after we edit it.  Otherwise the metadata provider
    // won't notice the change.
    long lastModified = tempSamlMetadata.lastModified();
    while (System.currentTimeMillis() <= (lastModified + 1000)) {
      Thread.sleep(1000);
    }
    Metadata metadata = Metadata.getInstanceForTest(HOST1);
    metadata
        .getResolver()
        .resolve(new CriteriaSet()); // Force the information to be read and cached.
    logger.info("Modifying metadata file");
    Document document = MetadataEditor.readMetadataDocument(tempSamlMetadata);
    MetadataEditor.addIdpEntity(document,
        MetadataEditor.SamlClientIdp.makeSso(
            CLIENT_ENTITY_ID, CLIENT_URL, CLIENT_ARTIFACT_URL, CLIENT_CERTIFICATE));
    MetadataEditor.writeMetadataDocument(document, tempSamlMetadata);
    logMetadataModified();
    metadata.refresh();
    try {
      metadata.getEntity(CLIENT_ENTITY_ID);
    } catch (IllegalArgumentException e) {
      fail("Expected entity to be present: " + CLIENT_ENTITY_ID);
    }
  }

  /**
   * Test that we properly replace any tokens in the saml-metadata file with
   * the configured GSA Entity Id.
   */
  public void testReplaceTokensInSamlConfigFile() throws Exception {
    String expectedGsaEntityId = C.entityIdForGsa(SecurityManagerTestCase.GSA_TESTING_ISSUER);
    String expectedSmEntityId = C.entityIdForSecMgr(SecurityManagerTestCase.GSA_TESTING_ISSUER);

    // the current iteration of what saml-metadata.xml looks like
    // which uses the ${GSA_ENTITY_ID} tag that needs to be replaced
    Metadata.setMetadataFile(
        new File(getClass().getResource("/saml-metadata.xml").getFile()));
    Metadata metadata = Metadata.getInstanceForTest("currenthost.com");
    assertEquals(expectedGsaEntityId, metadata.getGsaEntity().getEntityID());
    assertEquals(expectedSmEntityId, metadata.getSmEntity().getEntityID());

    // after 7.2, the secmgr string was {$GSA_ENTITY_ID}/security-manager
    // check that we replace this properly
    Metadata.setMetadataFile(
        new File(getClass().getResource("/saml-metadata-72.xml").getFile()));
    metadata = Metadata.getInstanceForTest("72host.com");
    assertEquals(expectedGsaEntityId, metadata.getGsaEntity().getEntityID());
    assertEquals(expectedSmEntityId, metadata.getSmEntity().getEntityID());

    // after 7.0, we used a simple hardcoded path, http://google.com/enterprise/gsa
    Metadata.setMetadataFile(
        new File(getClass().getResource("/saml-metadata-70.xml").getFile()));
    metadata = Metadata.getInstanceForTest("70host.com");
    assertEquals(expectedGsaEntityId, metadata.getGsaEntity().getEntityID());
    assertEquals(expectedSmEntityId, metadata.getSmEntity().getEntityID());

    // before 7.0, we used a hardcoded path with a ${ENT_CONFIG_NAME} tag that
    // would be replaced by the appliance ID. make sure we now replace it with
    // the proper value
    Metadata.setMetadataFile(
        new File(getClass().getResource("/saml-metadata-pre70.xml").getFile()));
    metadata = Metadata.getInstanceForTest("pre70host.com");
    assertEquals(expectedGsaEntityId, metadata.getGsaEntity().getEntityID());
    assertEquals(expectedSmEntityId, metadata.getSmEntity().getEntityID());

    // throughout all versions, we respected any path that was hardcoded that wasn't
    // our "magic ids/tags" (i.e. we don't replace them)
    Metadata.setMetadataFile(
        new File(getClass().getResource("/saml-metadata-fixedname.xml").getFile()));
    metadata = Metadata.getInstanceForTest("fixedname.com");
    assertEquals("http://some.id.name", metadata.getGsaEntity().getEntityID());
    assertEquals("http://some.other.id.name", metadata.getSmEntity().getEntityID());
  }

  /**
   * Test that we properly replace any tokens in the saml-metadata file with
   * the configured GSA Entity Id.
   */
  public void testReplaceTokensWithConfiguredEntityId() throws Exception {
    System.setProperty("gsa.applianceid", "FAKE_APPLIANCE_ID");
    assertEquals("FAKE_APPLIANCE_ID", SecurityManagerUtil.getGsaApplianceId());

    Metadata.setMetadataFile(new File(getClass().getResource("/saml-metadata.xml").getFile()));
    Metadata metadata = Metadata.getInstanceForTest("fakeid.com");
    assertEquals(C.entityIdForGsa("http://google.com/enterprise/gsa/FAKE_APPLIANCE_ID"),
        metadata.getGsaEntity().getEntityID());
    assertEquals(C.entityIdForSecMgr("http://google.com/enterprise/gsa/FAKE_APPLIANCE_ID"),
        metadata.getSmEntity().getEntityID());

    System.setProperty("gsa.entityid", "http://useme.com");
    assertEquals("http://useme.com", SecurityManagerUtil.getConfiguredEntityId());

    Metadata.setMetadataFile(new File(getClass().getResource("/saml-metadata.xml").getFile()));
    metadata = Metadata.getInstanceForTest("entityId.com");
    assertEquals(C.entityIdForGsa("http://useme.com"),
        metadata.getGsaEntity().getEntityID());
    assertEquals(C.entityIdForSecMgr("http://useme.com"),
        metadata.getSmEntity().getEntityID());

    // some manual, forced cleanup here
    System.setProperty("gsa.entityid", "");
    System.setProperty("gsa.applianceid", "");
  }

  public void testAdaptorEntityId() throws Exception {
    System.setProperty("gsa.applianceid", "FAKE_APPLIANCE_ID");
    assertEquals("FAKE_APPLIANCE_ID", SecurityManagerUtil.getGsaApplianceId());

    Metadata.setMetadataFile(new File(getClass().getResource("/saml-metadata.xml").getFile()));
    Metadata metadata = Metadata.getInstanceForTest("fakeid.com");
    assertEquals("http://google.com/enterprise/gsa/adaptor",
        metadata.getEntity("http://google.com/enterprise/gsa/adaptor").getEntityID());
  }

  private void logMetadataModified() {
    logger.info("Metadata file mod time: " + tempSamlMetadata.lastModified());
  }

  private EntityDescriptor findClientsDescriptor(Metadata metadata) throws ResolverException {
    for (EntityDescriptor child : metadata.getResolver().resolve(new CriteriaSet())) {
      if (MetadataEditor.SECMGR_CLIENTS_ENTITIES_NAME.equals(
          child.getUnknownAttributes().get(QName.valueOf("Name")))) {
        return child;
      }
    }
    return null;
  }
}
