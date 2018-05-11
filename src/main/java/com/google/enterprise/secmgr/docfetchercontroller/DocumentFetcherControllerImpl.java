// Copyright 2011 Google Inc.
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

package com.google.enterprise.secmgr.docfetchercontroller;

import com.google.common.annotations.VisibleForTesting;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.StringPair;
import com.google.enterprise.secmgr.http.BasicHttpAuthenticator;
import com.google.enterprise.secmgr.http.HttpRequester;
import com.google.enterprise.secmgr.http.KerberosHttpAuthenticator;
import com.google.enterprise.secmgr.http.NtlmHttpAuthenticator;
import com.google.enterprise.secmgr.http.PageFetcherResult;

import java.io.IOException;
import java.net.URL;
import java.util.logging.Logger;

import javax.inject.Inject;

/**
 * Default implementation of the document fetcher interface.
 * This implementation will simply download one document at a time, with the appropriate
 * credentials if necessary.
 */
public class DocumentFetcherControllerImpl implements DocumentFetcherController {
  private static final Logger logger =
      Logger.getLogger(DocumentFetcherControllerImpl.class.getName());

  @VisibleForTesting
  @Inject
  DocumentFetcherControllerImpl() {
  }

  @Override
  public PageFetcherResult fetch(String resource,
      Iterable<StringPair> headers,
      SessionView view) throws IOException {
    URL url = new URL(resource);
    HttpRequester requester = makeRequester(headers, view);
    PageFetcherResult result = requester.sendGet(url, true, null);
    logger.fine(
        view.logMessage("HttpRequest url: %s user: %s HTTP status: %d",
                        url, view.getUsername(), result.getStatusCode()));
    return result;
  }

  private static HttpRequester makeRequester(Iterable<StringPair> headers,
      SessionView view) {
    HttpRequester.Builder builder = HttpRequester.builder()
        .setSessionId(view.getSessionId())
        .setRequestId(view.getRequestId());

    // Basic and NTLM
    if (view.hasPrincipalAndPassword()) {
      builder
          .addAuthenticator(
              BasicHttpAuthenticator.make(view.getUsername(), view.getPassword()))
          .addAuthenticator(
              NtlmHttpAuthenticator.make(view.getDomain(), view.getUsername(),
                  view.getPassword()));
    }

    // Kerberos
    builder.addAuthenticator(KerberosHttpAuthenticator.make());

    // Form/Cookie
    builder.setAuthorityCookies(view.getAuthorityCookies());
    builder.setUserAgentCookies(view.getUserAgentCookies());

    // Some headers
    builder.setSendAdditionalHeaders(true);
    for (StringPair header : headers) {
      builder.addAdditionalHeader(header);
    }

    return builder.build();
  }

}
