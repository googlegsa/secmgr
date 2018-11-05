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

package com.google.enterprise.secmgr.config;

import static com.google.enterprise.secmgr.config.ConfigTestUtil.jsonBinding;
import static com.google.enterprise.secmgr.config.ConfigTestUtil.jsonObject;
import static com.google.enterprise.secmgr.config.ConfigTestUtil.jsonQuote;

import com.google.common.collect.Lists;
import com.google.enterprise.secmgr.servlets.SecurityManagerServletConfig;
import java.util.List;
import junit.framework.TestCase;

/**
 * Unit test for AuthnMechanism.
 */
public class AuthnMechanismTest extends TestCase {

  private static final String SAMPLE_URL_1 = "http://gama.corp.google.com/secured/";
  private static final String SAMPLE_URL_2 = "http://leiz.mtv.corp.google.com/basic/";

  public AuthnMechanismTest() {
    super();
    SecurityManagerServletConfig.initializeGson();
  }

  public void testMech1() {
    runMechTest(makeMech1());
  }

  public void testMech2() {
    runMechTest(makeMech2());
  }

  public void testMech3() {
    runMechTest(makeMech3());
  }

  private void runMechTest(AuthnMechanism expected) {
    AuthnMechanism mech
        = ConfigSingleton.getGson().fromJson(makeMechString(expected), AuthnMechanism.class);
    assertEquals(expected, mech);
  }

  public static AuthnMechanism makeMech1() {
    return AuthnMechForm.make("mech1", SAMPLE_URL_1);
  }

  public static AuthnMechanism makeMech2() {
    return AuthnMechBasic.make("mech2", SAMPLE_URL_2);
  }

  public static AuthnMechanism makeMech3() {
    return AuthnMechSaml.make("mech3", "leiz.mtv.corp.google.com");
  }

  public static String makeMechString(AuthnMechanism mech) {
    List<String> bindings = Lists.newArrayList();
    bindings.add(jsonBinding("typeName", jsonQuote(mech.getClass().getSimpleName())));
    if (mech instanceof AuthnMechBasic) {
      bindings.add(jsonBinding("sampleUrl", jsonQuote(mech.getSampleUrl())));
      bindings.add(jsonBinding("timeout", mech.getTimeout()));
      bindings.add(jsonBinding("trustDuration", mech.getTrustDuration()));
    } else if (mech instanceof AuthnMechConnector) {
      AuthnMechConnector mc = (AuthnMechConnector) mech;
      bindings.add(jsonBinding("connectorName", jsonQuote(mc.getConnectorName())));
      bindings.add(jsonBinding("doGroupLookupOnly", mc.doGroupLookupOnly()));
      bindings.add(jsonBinding("timeout", mech.getTimeout()));
      bindings.add(jsonBinding("trustDuration", mech.getTrustDuration()));
    } else if (mech instanceof AuthnMechForm) {
      bindings.add(jsonBinding("sampleUrl", jsonQuote(mech.getSampleUrl())));
      bindings.add(jsonBinding("timeout", mech.getTimeout()));
      bindings.add(jsonBinding("trustDuration", mech.getTrustDuration()));
    } else if (mech instanceof AuthnMechKerberos) {
    } else if (mech instanceof AuthnMechLdap) {
      AuthnMechLdap ml = (AuthnMechLdap) mech;
      bindings.add(jsonBinding("hostport", jsonQuote(ml.getHostport())));
      bindings.add(jsonBinding("bindDn", jsonQuote(ml.getBindDn())));
      bindings.add(jsonBinding("password", jsonQuote(ml.getPassword())));
      bindings.add(jsonBinding("searchBase", jsonQuote(ml.getSearchBase())));
      bindings.add(jsonBinding("userSearchFilter", jsonQuote(ml.getUserSearchFilter())));
      bindings.add(jsonBinding("groupSearchFilter", jsonQuote(ml.getGroupSearchFilter())));
      bindings.add(jsonBinding("sslSupport", ml.getSslSupport()));
      bindings.add(jsonBinding("supportedAuthMethods", ml.getSupportedAuthMethods()));
      bindings.add(jsonBinding("enableAuthn", ml.isEnableAuthn()));
      bindings.add(jsonBinding("enableGroupLookup", ml.isEnableGroupLookup()));
      bindings.add(jsonBinding("timeout", mech.getTimeout()));
      bindings.add(jsonBinding("trustDuration", ml.getTrustDuration()));
    } else if (mech instanceof AuthnMechNtlm) {
      bindings.add(jsonBinding("sampleUrl", jsonQuote(mech.getSampleUrl())));
      bindings.add(jsonBinding("timeout", mech.getTimeout()));
      bindings.add(jsonBinding("trustDuration", mech.getTrustDuration()));
    } else if (mech instanceof AuthnMechSaml) {
      bindings.add(jsonBinding("entityId", jsonQuote(((AuthnMechSaml) mech).getEntityId())));
      bindings.add(jsonBinding("timeout", mech.getTimeout()));
    } else if (mech instanceof AuthnMechSampleUrl) {
      AuthnMechSampleUrl m = (AuthnMechSampleUrl) mech;
      bindings.add(jsonBinding("sampleUrl", jsonQuote(m.getSampleUrl())));
      bindings.add(jsonBinding("redirectUrl", jsonQuote(m.getRedirectUrl())));
      bindings.add(jsonBinding("returnUrlParameter", jsonQuote(m.getReturnUrlParameter())));
      bindings.add(jsonBinding("timeout", mech.getTimeout()));
      bindings.add(jsonBinding("trustDuration", m.getTrustDuration()));
    } else if (mech instanceof AuthnMechGroups) {
      bindings.add(jsonBinding("timeout", mech.getTimeout()));
      bindings.add(jsonBinding("trustDuration", mech.getTrustDuration()));
    } else if (mech instanceof AuthnMechPreauthenticated) {
      AuthnMechPreauthenticated m = (AuthnMechPreauthenticated) mech;
      bindings.add(jsonBinding("timeout", mech.getTimeout()));
      bindings.add(jsonBinding("trustDuration", m.getTrustDuration()));
    } else {
      throw new IllegalArgumentException("Unknown mechanism: " + mech);
    }
    bindings.add(jsonBinding("name", jsonQuote(mech.getName())));
    return jsonObject(bindings);
  }
}
