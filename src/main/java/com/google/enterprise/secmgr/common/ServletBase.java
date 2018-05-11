// Copyright 2008 Google Inc.
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

package com.google.enterprise.secmgr.common;

import com.google.common.base.Preconditions;

import org.joda.time.DateTimeUtils;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletResponse;

/**
 * Useful utilities for writing servlets.
 */
public abstract class ServletBase extends HttpServlet {

  public static String httpDateString() {
    return HttpUtil.generateHttpDate(DateTimeUtils.currentTimeMillis());
  }

  public static PrintWriter initNormalResponse(HttpServletResponse response)
  throws IOException {
    return initNormalResponseWithHeaders(response, HttpServletResponse.SC_OK);
  }

  public static PrintWriter initNormalResponseWithHeaders(
      HttpServletResponse response, String... headerNameValuePairs) throws IOException {
    return initNormalResponseWithHeaders(response, HttpServletResponse.SC_OK, headerNameValuePairs);
  }

  public static PrintWriter initNormalResponse(HttpServletResponse response, int status)
      throws IOException {
    return initNormalResponseWithHeaders(response, status);
  }

  public static PrintWriter initNormalResponseWithHeaders(HttpServletResponse response,
      int status, String... headerNameValuePairs)
      throws IOException {
    Preconditions.checkArgument(headerNameValuePairs.length % 2 == 0);

    initResponse(response);
    response.setStatus(status);
    response.setContentType("text/html");
    response.setCharacterEncoding("UTF-8");
    response.setHeader("Content-Type", "text/html; charset=UTF-8");

    // Emit any requested headers
    for (int i = 0; i < headerNameValuePairs.length; i += 2) {
      String value = headerNameValuePairs[i + 1];
      if ((headerNameValuePairs[i] != null) && (value != null)) {
        response.setHeader(headerNameValuePairs[i], value);
      }
    }
    response.setBufferSize(0x1000);
    return response.getWriter();
  }
  
  public static ServletOutputStream initRawResponseWithHeaders(HttpServletResponse response,
      int status, String contentType, String... headerNameValuePairs) throws IOException {
    Preconditions.checkArgument(headerNameValuePairs.length % 2 == 0);
    
    initResponse(response);
    response.setStatus(status);
    response.setContentType(contentType);
    
    // Emit any requested headers
    for (int i = 0; i < headerNameValuePairs.length; i += 2) {
      String value = headerNameValuePairs[i + 1];
      if ((headerNameValuePairs[i] != null) && (value != null)) {
        response.setHeader(headerNameValuePairs[i], value);
      }
    }
    
    return response.getOutputStream();
  }

  public static void initErrorResponse(HttpServletResponse response, int code)
      throws IOException {
    initResponse(response);
    response.sendError(code);
  }

  private static boolean isNothing(String s) {
    return s == null || s.trim().isEmpty();
  }
  
  public static void sendRedirect(HttpServletResponse response, String destinationUrl) 
      throws IOException {
    initResponse(response);
    String newLocation = isNothing(destinationUrl) ? "/" : destinationUrl;
    response.sendRedirect(newLocation);
  }

  public static void initResponse(HttpServletResponse response) {
    response.setHeader("Date", httpDateString());
  }

  public static boolean isRedirectStatus(int status) {
    return status == HttpServletResponse.SC_SEE_OTHER || status == HttpServletResponse.SC_FOUND;
  }
}
