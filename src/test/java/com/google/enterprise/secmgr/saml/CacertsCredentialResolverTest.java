/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.enterprise.secmgr.saml;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.x509.X509Credential;

/**
 * Unit tests for {@link CacertsCredentialResolver}.
 */
public class CacertsCredentialResolverTest extends SecurityManagerTestCase {
  private static final Pattern NAME_PATTERN = Pattern.compile("[0-9.]+=#[0-9a-f]+,(.+)");
  private static final ImmutableSet<String> CERT_NAMES
      = ImmutableSet.of(
          "CN=Ondra's certification authority,OU=Enterprise,O=Google,ST=Switzerland,C=CH",
          "CN=Test Me,O=Google Inc.,L=Mountain View,ST=California,C=US",
          "CN=foo.ent.google.com,O=Google\\, Inc.,L=Mountain View,ST=California,C=US",
          "OU=Equifax Secure Certificate Authority,O=Equifax,C=US",
          "CN=GSA LDAP TESTING CA,OU=GSA LDAP TESTING,O=Google Inc,L=New York,ST=NY,C=US",
          "CN=http-auth-test.corp.google.com,O=Google.com,ST=ca,C=US");

  private final CacertsCredentialResolver resolver;
  private final CriteriaSet criteriaSet;

  public CacertsCredentialResolverTest()
      throws IOException, GeneralSecurityException {
    resolver = CacertsCredentialResolver.make(ConfigSingleton.getCacertsTrustStore());
    criteriaSet = new CriteriaSet(new EntityIDCriteria("dummyentityid"));
  }

  public void testSimple()
      throws SecurityException {
    ImmutableSet<String> certNames
        = ImmutableSet.copyOf(
            Iterables.transform(resolver.resolve(criteriaSet),
                new Function<Credential, String>() {
                  @Override
                  public String apply(Credential credential) {
                    X509Certificate cert = ((X509Credential) credential).getEntityCertificate();
                    return normalizeName(cert.getIssuerX500Principal().getName());
                  }
                }));
    assertEquals(CERT_NAMES, certNames);
  }

  private String normalizeName(String name) {
    while (true) {
      Matcher m = NAME_PATTERN.matcher(name);
      if (!m.matches()) {
        return name;
      }
      name = m.group(1);
    }
  }
}
