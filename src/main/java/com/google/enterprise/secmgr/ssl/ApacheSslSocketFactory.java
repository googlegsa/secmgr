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

import org.apache.http.conn.scheme.LayeredSchemeSocketFactory;
import org.apache.http.conn.scheme.LayeredSocketFactory;
import org.apache.http.conn.scheme.SchemeLayeredSocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.params.HttpParams;

import java.io.IOException;
import java.net.Socket;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;

/**
 * Class is a workaround for https://issues.apache.org/jira/browse/HTTPCLIENT-1119
 *
 */
public class ApacheSslSocketFactory extends SSLSocketFactory implements SchemeLayeredSocketFactory,
                                    LayeredSchemeSocketFactory, LayeredSocketFactory {

  public ApacheSslSocketFactory(final SSLContext sslContext,
                                final X509HostnameVerifier hostnameVerifier) {
    super(sslContext, hostnameVerifier);
  }   

  public Socket createSocket(final HttpParams params) throws IOException {
    return SocketFactory.getDefault().createSocket();
  }

  public Socket createSocket() throws IOException {
    return SocketFactory.getDefault().createSocket();
  }
}
