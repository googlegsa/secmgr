// Copyright 2013 Google Inc.
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

package com.google.enterprise.secmgr.http;

import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;
import java.net.Proxy;
import java.net.URI;
import java.util.List;

/**
 * Tests for the {@link ProxyConf} class.
 *
 */
public class ProxyConfTest extends SecurityManagerTestCase {
  private ProxyConf proxyConf;
  private ConfigurableProxySelector configurableProxySelector;

  @Override
  protected void setUp() throws Exception {
    super.setUp();
    proxyConf = new ProxyConf();
    proxyConf.setConfFile("proxies.enterprise");

    configurableProxySelector = new ConfigurableProxySelector(proxyConf);
  }

  public void testGetProxy() throws Exception {
    String proxy = proxyConf.getProxy("http://tests.com/");
    assertNotNull(proxy);
    assertEquals("proxy.com:3128", proxy);

    proxy = proxyConf.getProxy("http://tests.com");
    assertNull(proxy);

    proxy = proxyConf.getProxy("http://tests.com/abc");
    assertNotNull(proxy);
    assertEquals("proxy.com:3128", proxy);

    proxy = proxyConf.getProxy("tests.com/abc");
    assertNull(proxy);

    proxy = proxyConf.getProxy("http://www.tests.com/");
    assertNull(proxy);

    proxy = proxyConf.getProxy("http://www.another.com/");
    assertNotNull(proxy);
    assertEquals("1.2.3.4:3129", proxy);

    proxy = proxyConf.getProxy("http://another.com/");
    assertNotNull(proxy);
    assertEquals("1.2.3.4:3128", proxy);

    proxy = proxyConf.getProxy("http://notcovered.com/");
    assertNull(proxy);

    URI uri = new URI("http://tests.com/");
    List<Proxy> listSelectedProxies = configurableProxySelector.select(uri);
    assertNotNull(listSelectedProxies);
    assertTrue(
        listSelectedProxies
            .get(0)
            .toString()
            .matches("HTTP @ proxy.com(\\/.*)?:3128"));
  }
}
