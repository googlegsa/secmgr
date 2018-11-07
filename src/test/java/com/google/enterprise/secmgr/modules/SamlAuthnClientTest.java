// Copyright 2015 Google Inc.
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

import static com.google.enterprise.secmgr.modules.SamlAuthnClient.verifySignatureBasedOnMetadataInternal;

import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.logging.Logger;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.provider.DOMMetadataProvider;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Tests for the {@link SamlAuthnClient} class.
 *
 * <p>This class is not easy to be created and tested alone. Right now, just test newly added logic
 * of verifying signed assertion.
 */
public class SamlAuthnClientTest extends SecurityManagerTestCase {
  private static final Logger logger = Logger.getLogger(SamlAuthnClientTest.class.getName());

  private static final String RESPONSE_FILE = "/saml-response.xml";
  private static final String METADATA_FILE = "/saml-metadata.xml";
  private static final String TRUSTED_CERT_FILE = "/saml-client-test.crt";
  private static final String TRUSTED_PRIVKEY_FILE = "/saml-client-test.key";
  private static final String UNTRUSTED_CERT_FILE = "/saml-client-test-untrusted.crt";
  private static final String UNTRUSTED_PRIVKEY_FILE = "/saml-client-test-untrusted.key";

  private BasicParserPool parser;
  private MarshallerFactory marshallerFactory;
  private UnmarshallerFactory unmarshallerFactory;
  private DOMMetadataProvider mdProvider;

  public SamlAuthnClientTest() throws Exception {
    // Since we don't use OpenSamlUtil here, we need to bootstrap OpenSaml library.
    DefaultBootstrap.bootstrap();
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();

    marshallerFactory = Configuration.getMarshallerFactory();
    unmarshallerFactory = Configuration.getUnmarshallerFactory();

    parser = new BasicParserPool();
    parser.setNamespaceAware(true);
    InputStream in = new FileInputStream(getClass().getResource(METADATA_FILE).getFile());
    mdProvider = new DOMMetadataProvider(parser.parse(in).getDocumentElement());
    mdProvider.initialize();
    in.close();
  }

  public void testVerifyAssertionSignedByTrustedIssuerSuccess() throws Exception {
    Response resp = buildResponseFromFile();
    Assertion assertion = resp.getAssertions().get(0);

    Signature signature = buildSignature(
        getX509CredentialHelper(TRUSTED_CERT_FILE, TRUSTED_PRIVKEY_FILE));
    assertion.setSignature(signature);

    Marshaller marshaller = marshallerFactory.getMarshaller(Response.DEFAULT_ELEMENT_NAME);
    marshaller.marshall(resp);
    Signer.signObject(signature);
    logger.info(XMLHelper.nodeToString(resp.getDOM()));

    assertEquals(true, verifySignatureBasedOnMetadataInternal(assertion, mdProvider));
  }

  public void testVerifyAssertionSignedByUntrustedIssuerFail() throws Exception {
    Response resp = buildResponseFromFile();
    Assertion assertion = resp.getAssertions().get(0);

    Signature signature = buildSignature(
        getX509CredentialHelper(UNTRUSTED_CERT_FILE, UNTRUSTED_PRIVKEY_FILE));
    assertion.setSignature(signature);

    Marshaller marshaller = marshallerFactory.getMarshaller(Response.DEFAULT_ELEMENT_NAME);
    marshaller.marshall(resp);
    Signer.signObject(signature);
    logger.info(XMLHelper.nodeToString(resp.getDOM()));

    assertEquals(false, verifySignatureBasedOnMetadataInternal(assertion, mdProvider));
  }

  public void testVerifyAssertionWithNonmatchingIssuer() throws Exception {
    Response resp = buildResponseFromFile();
    Assertion assertion = resp.getAssertions().get(0);

    Issuer issuer = (Issuer) Configuration.getBuilderFactory()
        .getBuilder(Issuer.DEFAULT_ELEMENT_NAME)
        .buildObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue("nonmatching issuer");
    assertion.setIssuer(issuer);

    Signature signature = buildSignature(
        getX509CredentialHelper(TRUSTED_CERT_FILE, TRUSTED_PRIVKEY_FILE));
    assertion.setSignature(signature);

    Marshaller marshaller = marshallerFactory.getMarshaller(Response.DEFAULT_ELEMENT_NAME);
    marshaller.marshall(resp);
    Signer.signObject(signature);
    logger.info(XMLHelper.nodeToString(resp.getDOM()));

    assertEquals(false, verifySignatureBasedOnMetadataInternal(assertion, mdProvider));
  }

  public void testVerifyNoSignedAssertionFail() throws Exception {
    Response resp = buildResponseFromFile();
    assertEquals(false,
        verifySignatureBasedOnMetadataInternal(resp.getAssertions().get(0), mdProvider));
  }

  private Response buildResponseFromFile() throws Exception {
    InputStream in = new FileInputStream(
        new File(getClass().getResource(RESPONSE_FILE).getFile()));
    Document doc = parser.parse(in);
    Element samlElement = doc.getDocumentElement();
    in.close();

    Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElement);
    return (Response) unmarshaller.unmarshall(samlElement);
  }

  private static Signature buildSignature(Credential signingCredential) {
    Signature signature = (Signature) Configuration.getBuilderFactory()
        .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
        .buildObject(Signature.DEFAULT_ELEMENT_NAME);

    signature.setSigningCredential(signingCredential);
    signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
    return signature;
  }

  private static Credential getX509CredentialHelper(String certFilename, String privKeyFilename)
      throws Exception {
    X509Certificate cert = SecurityHelper.buildJavaX509Cert(
        readPemFileAndRemoveBeginEnd(certFilename));
    RSAPrivateKey privateKey = SecurityHelper.buildJavaRSAPrivateKey(
        readPemFileAndRemoveBeginEnd(privKeyFilename));
    return SecurityHelper.getSimpleCredential(cert, privateKey);
  }

  private static String readPemFileAndRemoveBeginEnd(String filename) throws Exception {
    byte[] encoded =
        Files.readAllBytes(Paths.get(SamlAuthnClientTest.class.getResource(filename).getFile()));
    String str = new String(encoded, StandardCharsets.UTF_8);
    str = str.replace("\n", "");
    str = str.replace("-----BEGIN CERTIFICATE-----", "");
    str = str.replace("-----END CERTIFICATE-----", "");
    str = str.replace("-----BEGIN RSA PRIVATE KEY-----", "");
    str = str.replace("-----END RSA PRIVATE KEY-----", "");
    logger.info(str);
    return str;
  }
}
