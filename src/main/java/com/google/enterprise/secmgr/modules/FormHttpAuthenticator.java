// Copyright 2010 Google Inc.
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

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.ListMultimap;
import com.google.enterprise.logmanager.LogClient;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HtmlParser;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.http.HttpAuthenticator;
import com.google.enterprise.secmgr.http.HttpRequester;
import com.google.enterprise.secmgr.http.PageFetcherResult;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.IOException;
import java.net.URL;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;

/**
 * An authenticator that handles HTTP Form authentication.
 */
@Immutable
public final class FormHttpAuthenticator implements HttpAuthenticator {
  private static final Logger logger = Logger.getLogger(FormHttpAuthenticator.class.getName());
  private static final LogClient gsaLogger = new LogClient("Security Manager",
      SecurityManagerUtil.getLogManagerServer());
  private static final int PREFERENCE_RANK = 1;

  private final String username;
  private final String password;
  private final URL formUrl;
  private final Element formElement;

  private FormHttpAuthenticator(String username, String password, URL formUrl,
      Element formElement) {
    this.username = username;
    this.password = password;
    this.formUrl = formUrl;
    this.formElement = formElement;
  }

  static HttpAuthenticator make(String username, String password, URL formUrl,
      Element formElement) {
    Preconditions.checkArgument(!Strings.isNullOrEmpty(username));
    Preconditions.checkArgument(!Strings.isNullOrEmpty(password));
    Preconditions.checkNotNull(formElement);
    return new FormHttpAuthenticator(username, password, formUrl, formElement);
  }

  @Override
  public boolean isApplicable(PageFetcherResult previousResult) {
    return HttpUtil.isGoodHttpStatus(previousResult.getStatusCode());
        //&& (previousResult.getRedirectUrl() != null);
  }

  @Override
  public int getPreferenceRank() {
    return PREFERENCE_RANK;
  }

  @Override
  public PageFetcherResult apply(PageFetcherResult previousResult, HttpRequester requester, URL url,
      boolean getBody)
      throws IOException {

    String sessionId = requester.getSessionId();
    String requestId = requester.getRequestId();

    logFormParts(formElement, sessionId, requestId);

    ListMultimap<String, String> parameters
        = getSubmissionParameters(formElement, username, password, sessionId, requestId);

    URL submitUrl;
    if (formUrl != null) {
      submitUrl = formUrl;
    } else {
      submitUrl = url;
    }
    URL actionUrl = makeSubmitUrl(formElement.getAttribute(HtmlParser.ATTR_ACTION), submitUrl);

    return HttpRequester.builder()
        .setUserAgentCookies(requester.getUserAgentCookies())
        .setAuthorityCookies((previousResult == null)
            ? requester.getAuthorityCookies()
            : GCookie.mergeCookies(
                requester.getAuthorityCookies(),
                previousResult.getReceivedCookies()))
        .setTimeout(requester.getTimeout())
        .setSessionId(requester.getSessionId())
        .setRequestId(requester.getRequestId())
        .build()
        .sendPost(actionUrl, parameters, false, previousResult);
  }

  private URL makeSubmitUrl(String action, URL formUrl) throws IOException {
    return (action == null) ? formUrl : new URL(formUrl, action);
  }

  private ListMultimap<String, String> getSubmissionParameters(Element formElement, String username,
      String password, String sessionId, String requestId)
      throws IOException {

    // Look for "text" and "password" inputs, and fill them in.  If there are
    // multiple such inputs, ignore all but the first of each.
    boolean haveUser = false;
    boolean havePass = false;
    ImmutableListMultimap.Builder<String, String> paramBuilder = ImmutableListMultimap.builder();

    NodeList inputs = formElement.getElementsByTagName(HtmlParser.TAG_INPUT);
    for (int i = 0; i < inputs.getLength(); i++) {
      Element input = Element.class.cast(inputs.item(i));
      String inputType = HtmlParser.getInputType(input);
      String inputName = input.getAttribute(HtmlParser.ATTR_NAME);

      if (HtmlParser.INPUT_TYPE_TEXT.equals(inputType)) {
        if (!haveUser) {

          paramBuilder.put(inputName, username);
          haveUser = true;
        }
      } else if (HtmlParser.INPUT_TYPE_PASSWORD.equals(inputType)) {
        if (!havePass) {

          paramBuilder.put(inputName, password);
          havePass = true;
        }
      } else if (HtmlParser.INPUT_TYPE_HIDDEN.equals(inputType)) {

        paramBuilder.put(inputName, input.getAttribute(HtmlParser.ATTR_VALUE));
      }
    }

    if (!(haveUser && havePass)) {
      String message = "Login form doesn't have both text and password inputs";
      logger.warning(SessionUtil.logMessage(sessionId, message));
      gsaLogger.log(requestId, message);
      throw new IOException(message);
    }
    return paramBuilder.build();
  }

  private static void logFormParts(Element formElement, String sessionId, String requestId) {

    String name = formElement.getAttribute(HtmlParser.ATTR_NAME);
    String action = formElement.getAttribute(HtmlParser.ATTR_ACTION);
    NodeList inputs = formElement.getElementsByTagName(HtmlParser.TAG_INPUT);

    StringBuffer logBuffer = new StringBuffer("Got form");
    addToLogBuffer(";", HtmlParser.ATTR_NAME, name, logBuffer);
    addToLogBuffer(";", HtmlParser.ATTR_ACTION, action, logBuffer);
    for (int i = 0; i < inputs.getLength(); i++) {
      Element input = Element.class.cast(inputs.item(i));
      addToLogBuffer(";", HtmlParser.ATTR_TYPE, HtmlParser.getInputType(input), logBuffer);
      addToLogBuffer(",", HtmlParser.ATTR_NAME,
                     input.getAttribute(HtmlParser.ATTR_NAME), logBuffer);
    }
    logger.info(SessionUtil.logMessage(sessionId, logBuffer.toString()));
    gsaLogger.log(requestId, logBuffer.toString());
  }

  private static void addToLogBuffer(String separator, String tagName, String tagValue,
                                     StringBuffer logBuffer) {
    if (tagValue != null && !tagValue.isEmpty()) {
      logBuffer.append(separator);
      logBuffer.append(" ");
      logBuffer.append(tagName);
      logBuffer.append("=");
      logBuffer.append(tagValue);
    }
  }

}
