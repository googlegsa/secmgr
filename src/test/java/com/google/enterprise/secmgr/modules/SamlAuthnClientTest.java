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

import com.google.enterprise.secmgr.modules.SamlAuthnClient.RedirectEncoder;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.metadata.resolver.impl.DOMMetadataResolver;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.ArtifactResponseBuilder;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
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
  private DOMMetadataResolver mdResolver;

  public SamlAuthnClientTest() throws Exception {
    // Since we don't use OpenSamlUtil here, we need to bootstrap OpenSaml library.
    InitializationService.initialize();
  }

  @Override
  public void setUp() throws Exception {
    super.setUp();

    marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
    unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();

    parser = new BasicParserPool();
    parser.setNamespaceAware(true);
    parser.initialize();
    InputStream in = new FileInputStream(getClass().getResource(METADATA_FILE).getFile());
    mdResolver = new DOMMetadataResolver(parser.parse(in).getDocumentElement());
    mdResolver.setId(getClass().getName());
    mdResolver.initialize();
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
    logger.info(SerializeSupport.nodeToString(resp.getDOM()));

    assertTrue(verifySignatureBasedOnMetadataInternal(assertion, mdResolver));
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
    logger.info(SerializeSupport.nodeToString(resp.getDOM()));

    assertFalse(verifySignatureBasedOnMetadataInternal(assertion, mdResolver));
  }

  public void testVerifyAssertionWithNonmatchingIssuer() throws Exception {
    Response resp = buildResponseFromFile();
    Assertion assertion = resp.getAssertions().get(0);

    Issuer issuer =
        (Issuer)
            XMLObjectProviderRegistrySupport.getBuilderFactory()
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
    logger.info(SerializeSupport.nodeToString(resp.getDOM()));

    assertFalse(verifySignatureBasedOnMetadataInternal(assertion, mdResolver));
  }

  public void testVerifyNoSignedAssertionFail() throws Exception {
    Response resp = buildResponseFromFile();
    assertFalse(verifySignatureBasedOnMetadataInternal(resp.getAssertions().get(0), mdResolver));
  }
  
  public void testRedirectEncoderWithMalformedURL() {
    String url = "unkownproto://validhost.tld/path?queryA=b&queryB=c";
    MessageContext<SAMLObject> context = new MessageContext<>();
    context.setMessage(new ArtifactResponseBuilder().buildObject());
    try {
      new RedirectEncoder().buildRedirectURL(context, url, "msg");
      fail();
    } catch (MessageEncodingException e) {
      // OK
    }
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
    Signature signature =
        (Signature)
            XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

    signature.setSigningCredential(signingCredential);
    signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
    return signature;
  }

  private static Credential getX509CredentialHelper(String certFilename, String privKeyFilename)
      throws Exception {
    String certPath = SamlAuthnClientTest.class.getResource(certFilename).getFile();
    String keyPath = SamlAuthnClientTest.class.getResource(privKeyFilename).getFile();
    X509Certificate cert = OpenSamlUtil.readX509CertificateFile(new File(certPath));
    PrivateKey privateKey = OpenSamlUtil.readPrivateKeyFile(new File(keyPath));
    return CredentialSupport.getSimpleCredential(cert, privateKey);
  }
}
