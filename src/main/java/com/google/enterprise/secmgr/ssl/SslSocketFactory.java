// Copyright 2018 Google Inc.
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

package com.google.enterprise.secmgr.ssl;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocketFactory;

/**
 * SocketFactory implementation that wraps SecMgr's SslContext.
 *
 * This class is used only to satisfy LDAPClient's JNDI usage.
 *
 */
public class SslSocketFactory extends SSLSocketFactory {

  private SslSocketFactory() {
    super();
  }

  public static SslSocketFactory getDefault() {
    return new SslSocketFactory();
  }

  @Override
  public Socket createSocket(String host, int port)
      throws IOException, UnknownHostException {
    return SslContextFactory.getSocketFactory().createSocket(host, port);
  }

  @Override
  public Socket createSocket(String host, int port, InetAddress localHost,
      int localPort) throws IOException, UnknownHostException {
    return SslContextFactory.getSocketFactory().createSocket(
        host, port, localHost, localPort);
  }

  @Override
  public Socket createSocket(InetAddress host, int port) throws IOException {
    return SslContextFactory.getSocketFactory().createSocket(host, port);
  }

  @Override
  public Socket createSocket(InetAddress address, int port,
      InetAddress localAddress, int localPort) throws IOException {
    return SslContextFactory.getSocketFactory().createSocket(
        address, port, localAddress, localPort);
  }

  @Override
  public String[] getDefaultCipherSuites() {
    return SslContextFactory.getSocketFactory().getDefaultCipherSuites();
  }

  @Override
  public String[] getSupportedCipherSuites() {
    return SslContextFactory.getSocketFactory().getSupportedCipherSuites();
  }

  @Override
  public Socket createSocket(Socket s, String host, int port, boolean autoClose)
      throws IOException {
    return SslContextFactory.getSocketFactory().createSocket(s, host, port, autoClose);
  }
}
