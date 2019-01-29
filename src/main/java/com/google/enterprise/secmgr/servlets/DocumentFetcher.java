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

package com.google.enterprise.secmgr.servlets;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.net.InetAddresses;
import com.google.enterprise.secmgr.authncontroller.AuthnSession;
import com.google.enterprise.secmgr.authncontroller.AuthnSession.AuthnState;
import com.google.enterprise.secmgr.authncontroller.AuthnSessionManager;
import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.common.StringPair;
import com.google.enterprise.secmgr.docfetchercontroller.DocumentFetcherController;
import com.google.enterprise.secmgr.http.PageFetcherResult;
import com.google.inject.Singleton;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Simple servlet to download a document as an authenticated user.
 */
@Singleton
public class DocumentFetcher extends ServletBase implements PostableHttpServlet {
  private static final Logger logger = Logger.getLogger(DocumentFetcher.class.getName());
  private final DocumentFetcherController controller;
  private final AuthnSessionManager sessionManager;

  @VisibleForTesting
  @Inject
  DocumentFetcher(DocumentFetcherController controller, AuthnSessionManager sessionManager) {
    this.controller = controller;
    this.sessionManager = sessionManager;
  }
  
  @VisibleForTesting
  boolean isAllowed(HttpServletRequest req) {
    try {
      InetAddress remoteIp = InetAddresses.forString(req.getRemoteAddr());
      if (!remoteIp.isLoopbackAddress()) {
        logger.warning("Unauthorized access to this servlet.");
        return false;
      }
    } catch (IllegalArgumentException exp) {
      logger.warning("Unable to parse the remote IP: " + req.getRemoteAddr());
      return false;
    }
    return true;
  }
  
  @VisibleForTesting
  AuthnSession getSession(HttpServletRequest req) throws IOException {
    AuthnSession session = sessionManager.findSession(req);
    
    if (session == null) {
      session = sessionManager.createSession();
      logger.info(SessionUtil.logMessage(
          session.getSessionId(), "Looks like this request was issued during a public search."));
    }
    
    if(session.getState() != AuthnState.IDLE) {
      logger.warning(SessionUtil.logMessage(session.getSessionId(), "Session is not idle"));
      return null;
    }
    
    return session;
  }

  @Override
  public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
    if (!isAllowed(req)) {
      initErrorResponse(res, HttpServletResponse.SC_FORBIDDEN);
      return;
    }
    
    AuthnSession session = getSession(req);
    if (session == null) {
      initErrorResponse(res, HttpServletResponse.SC_CONFLICT);
      return;
    }
   
    String url = req.getParameter("url");
    logger.info("Got DocumentFetcher request for: " + url);
    
    String acceptHeader = req.getHeader(HttpUtil.HTTP_HEADER_ACCEPT);
    String acceptEncodingHeader = req.getHeader(HttpUtil.HTTP_HEADER_ACCEPT_ENCODING);
    
    ImmutableList<StringPair> headers = ImmutableList.of(
        new StringPair(HttpUtil.HTTP_HEADER_ACCEPT,
            (acceptHeader != null) ? acceptHeader : HttpUtil.ACCEPT_FOR_HEAD),
        new StringPair(HttpUtil.HTTP_HEADER_ACCEPT_ENCODING,
            (acceptEncodingHeader != null) ? acceptEncodingHeader : HttpUtil.ACCEPT_ENCODING));
    
    SessionSnapshot snapshot = session.getSnapshot();
    PageFetcherResult result = controller.fetch(url, headers, snapshot.getView());

    if (result == null || !HttpUtil.isGoodHttpStatus(result.getStatusCode())) {
      logger.warning(SessionUtil.logMessage(session.getSessionId(), "Unable to retrieve " + url));
      initErrorResponse(res, HttpServletResponse.SC_UNAUTHORIZED);
      return;
    }

    String contentType = result.getHeaderValue(HttpUtil.HTTP_HEADER_CONTENT_TYPE);
    OutputStream out = initRawResponseWithHeaders(res, HttpServletResponse.SC_OK,
        (contentType != null) ? contentType : HttpUtil.TYPE_OCTET_STREAM);
    
    res.setContentLength(result.getRawBody().length);
    out.write(result.getRawBody());
    return;
  }
}
