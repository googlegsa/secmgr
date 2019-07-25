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

package com.google.enterprise.secmgr.saml;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.XmlUtil;
import com.google.enterprise.secmgr.saml.MetadataEditor.SamlClientIdp;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import javax.xml.namespace.QName;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Unit tests for the SAML metadata editor.
 */
public class MetadataEditorTest extends SecurityManagerTestCase {

  private static final String URL1 = "http://example.com/foo/";
  private static final String URL2 = "http://example.com/bar/";
  private static final String URL3 = "http://example.com/baz/";

  private Document base;
  private File file;
  private String filecontents;
  private String clientCert;

  @Override
  public void setUp() throws Exception {
    super.setUp();
    base = MetadataEditor.makeOnboardSecurityManagerMetadata();
    file = new File(FileUtil.getCommonDirectory(), "test-metadata.xml");
    file.delete();
    FileWriter fileWriter = new FileWriter(file);
    MetadataEditor.writeMetadataDocument(base, fileWriter);
    fileWriter.close();
    filecontents = slurpFile(file);
    clientCert
        = MetadataEditor.normalizeCertificate(
            slurpFile(FileUtil.getContextFile("saml-client-test.crt")));
  }

  public void testGetClients() throws Exception {
    List<SamlClientIdp> clients = MetadataEditor.getSamlClientsInMetadata(filecontents);
    assertEquals(0, clients.size());
  }

  public void testMissingCertificate() throws Exception {
    List<SamlClientIdp> clients
        = MetadataEditor.getSamlClientsInMetadata(
            slurpFile(FileUtil.getContextFile("saml-metadata-b3159734.xml")));
    assertEquals(0, clients.size());
  }

  public void testSetClients() throws Exception {
    List<SamlClientIdp> clients1 = ImmutableList.of(makeClient(URL1), makeClient(URL2));
    String contents2 = MetadataEditor.setSamlClientsInMetadata(filecontents, clients1);

    List<SamlClientIdp> clients2 = MetadataEditor.getSamlClientsInMetadata(contents2);
    assertEquals(clients1, clients2);

    List<SamlClientIdp> clients3 = ImmutableList.of(makeClient(URL3));
    String contents3 = MetadataEditor.setSamlClientsInMetadata(filecontents, clients3);

    List<SamlClientIdp> clients4 = MetadataEditor.getSamlClientsInMetadata(contents3);
    assertEquals(clients3, clients4);
  }

  public void testAddClients() throws Exception {
    List<SamlClientIdp> clients1 = ImmutableList.of(makeClient(URL1));
    String contents2 = MetadataEditor.addSamlClientsToMetadata(filecontents, clients1);

    List<SamlClientIdp> clients2 = MetadataEditor.getSamlClientsInMetadata(contents2);
    assertEquals(clients1, clients2);

    List<SamlClientIdp> clients3 = ImmutableList.of(makeClient(URL2), makeClient(URL3));
    String contents3 = MetadataEditor.addSamlClientsToMetadata(contents2, clients3);

    List<SamlClientIdp> clients4 = MetadataEditor.getSamlClientsInMetadata(contents3);
    List<SamlClientIdp> clients5 = Lists.newArrayList();
    clients5.addAll(clients1);
    clients5.addAll(clients3);
    assertEquals(clients5, clients4);
  }

  public void testDetailedStructure() throws Exception {
    // Make a document with a specific set of clients.
    SamlClientIdp client0 = makeClient(URL1);
    SamlClientIdp client1 = makeClient(URL2, clientCert);
    List<SamlClientIdp> clients = ImmutableList.of(client0, client1);
    String contents = MetadataEditor.setSamlClientsInMetadata(filecontents, clients);

    // Parse the document and extract the clients.
    Document document = MetadataEditor.stringToMetadataDocument(contents);
    Element entities = MetadataEditor.getSamlClients(document);
    assertNotNull(entities);
    List<Element> children =
        XmlUtil.getChildElements(entities, MetadataEditor.SAML_DESCRIPTOR_ENTITY);
    assertEquals(2, children.size());

    // Compare the parsed clients to the original ones.
    Element entity0 = children.get(0);
    Element entity1 = children.get(1);
    if (client0.getId().equals(entity0.getAttribute(MetadataEditor.SAML_ATTR_ENTITY_ID))) {
      assertMatchingEntity(client0, entity0);
      assertMatchingEntity(client1, entity1);
    } else {
      assertMatchingEntity(client0, entity1);
      assertMatchingEntity(client1, entity0);
    }
  }

  private static void assertMatchingEntity(SamlClientIdp client, Element entity) {
    assertEquals(client.getId(), entity.getAttribute(MetadataEditor.SAML_ATTR_ENTITY_ID));
    Element role = getUniqueChild(entity, MetadataEditor.SAML_DESCRIPTOR_IDP_SSO);
    Element ssoElement = getUniqueChild(role, MetadataEditor.SAML_SERVICE_SINGLE_SIGN_ON);
    assertEquals(client.getUrl(), ssoElement.getAttribute(MetadataEditor.SAML_ATTR_LOCATION));
    if (client.getArtifactUrl() == null) {
      assertNoChild(role, MetadataEditor.SAML_SERVICE_ARTIFACT_RESOLUTION);
    } else {
      Element arsElement = getUniqueChild(role, MetadataEditor.SAML_SERVICE_ARTIFACT_RESOLUTION);
      assertEquals(client.getArtifactUrl(),
          arsElement.getAttribute(MetadataEditor.SAML_ATTR_LOCATION));
      assertEquals("0", arsElement.getAttribute(MetadataEditor.SAML_ATTR_INDEX));
      assertEquals("true", arsElement.getAttribute(MetadataEditor.SAML_ATTR_IS_DEFAULT));
    }
    if (client.getCertificate() == null) {
      assertNoChild(role, MetadataEditor.SAML_DESCRIPTOR_KEY);
    } else {
      Element keyDescriptor = getUniqueChild(role, MetadataEditor.SAML_DESCRIPTOR_KEY);
      Element keyInfo = getUniqueChild(keyDescriptor, MetadataEditor.XMLDSIG_KEY_INFO);
      Element x509Data = getUniqueChild(keyInfo, MetadataEditor.XMLDSIG_X509_DATA);
      Element x509Certificate = getUniqueChild(x509Data, MetadataEditor.XMLDSIG_X509_CERTIFICATE);
      NodeList nodes = x509Certificate.getChildNodes();
      assertEquals(1, nodes.getLength());
      assertEquals(Node.TEXT_NODE, nodes.item(0).getNodeType());
      assertEquals(client.getCertificate(), nodes.item(0).getNodeValue());
    }
  }

  private static Element getUniqueChild(Element parent, QName qname) {
    List<Element> elements = XmlUtil.getChildElements(parent, qname);
    assertEquals(1, elements.size());
    return elements.get(0);
  }

  private static void assertNoChild(Element parent, QName qname) {
    List<Element> elements = XmlUtil.getChildElements(parent, qname);
    assertTrue(elements.isEmpty());
  }

  private static SamlClientIdp makeClient(String root) {
    return SamlClientIdp.makeSso(root,
        root + "single-sign-on/",
        root + "artifact-resolution/",
        null);
  }

  private static SamlClientIdp makeClient(String root, String cert) {
    return (cert == null)
        ? makeClient(root)
        : SamlClientIdp.makeSso(root, root + "single-sign-on/", null, cert);
  }

  private static String slurpFile(String fileName) throws IOException {
    StringBuilder sb = new StringBuilder(1024);
    BufferedReader reader = new BufferedReader(new FileReader(fileName));

    try {
      char[] chars = new char[1024];
      int numRead = 0;
      while ((numRead = reader.read(chars)) > -1) {
        sb.append(String.valueOf(chars), 0, numRead);
      }
    } finally {
      reader.close();
    }

    return sb.toString();
  }

  private static String slurpFile(File file) throws IOException {
    return slurpFile(file.getAbsolutePath());
  }
}
