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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * A ProxySelector that select proxy based on configuration.
 *
 */
class ConfigurableProxySelector extends ProxySelector {
  static final List<Proxy> NO_PROXY_LIST = Arrays.asList(Proxy.NO_PROXY);

  private static final Logger logger = Logger.getLogger(ConfigurableProxySelector.class.getName());

  private ProxyConfInterface proxyConf;

  ConfigurableProxySelector(ProxyConfInterface proxyConf) {
    this.proxyConf = proxyConf;
  }

  @Override
  public List<Proxy> select(URI uri) {
    String formattedUri = uri.toString().endsWith("/") ? uri.toString() : uri + "/";

    String proxy = proxyConf.getProxy(formattedUri);
    if (proxy != null) {
      try {
        // Proxy format is host:port.
        URI proxyURI = new URI("http://" + proxy);
        return Arrays.asList(new Proxy(Proxy.Type.HTTP,
            new InetSocketAddress(proxyURI.getHost(), proxyURI.getPort())));
      } catch (URISyntaxException e) {
        return NO_PROXY_LIST;
      }
    }

    return NO_PROXY_LIST;
  }

  @Override
  public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
    logger.info("Connection to " + uri + " failed.");
  }
}
