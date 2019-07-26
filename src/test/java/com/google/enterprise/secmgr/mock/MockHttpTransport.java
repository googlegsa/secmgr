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

package com.google.enterprise.secmgr.mock;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Maps;
import com.google.common.collect.Multimap;
import com.google.enterprise.secmgr.common.GettableHttpServlet;
import com.google.enterprise.secmgr.common.HttpTransport;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.PostableHttpServlet;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.testing.ExchangeLog;
import com.google.enterprise.secmgr.testing.ExchangeLog.Builder;
import com.google.enterprise.secmgr.testing.ServletTestUtil;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;

/**
 * A trivial HttpTransport that just maps request URLs to registered servlets.
 */
public final class MockHttpTransport implements HttpTransport {

  /**
   * A set of identifiers that can be used to identity the HTTP messages
   * supported by a servlet.
   */
  public enum ServletCapabilities {
    GETTABLE, POSTABLE, GETTABLE_AND_POSTABLE
  }

  public interface RequestAction {
    public void apply(HttpServletRequest request);
  }

  public interface ResponseAction {
    public void apply(HttpServletResponse response);
  }

  private static final Logger logger = Logger.getLogger(MockHttpTransport.class.getName());
  public static boolean logMessages = true;

  private final Map<String, HttpServlet> getMap;
  private final Map<String, HttpServlet> postMap;
  private final Map<String, MockServletContext> contextMap;
  private final Map<EntityDescriptor, String> entityMap;
  private final Map<String, String> urlAliases;
  private final ExchangeLog.Builder exchangeLogBuilder;
  private final Multimap<Class<? extends HttpServlet>, RequestAction> requestActions;
  private final Multimap<Class<? extends HttpServlet>, ResponseAction> responseActions;

  public MockHttpTransport() {
    getMap = Maps.newHashMap();
    postMap = Maps.newHashMap();
    contextMap = Maps.newHashMap();
    entityMap = Maps.newHashMap();
    urlAliases = Maps.newHashMap();
    exchangeLogBuilder = new Builder();
    requestActions = ArrayListMultimap.create();
    responseActions = ArrayListMultimap.create();
  }

  public void registerContextUrl(String contextUrl) {
    if (contextMap.get(contextUrl) == null) {
      MockServletContext context = new MockServletContext();
      URL parsedUrl = HttpUtil.parseUrlString(contextUrl);
      if (parsedUrl != null) {
        context.setContextPath(parsedUrl.getPath());
      }
      contextMap.put(contextUrl, context);
    }
  }

  public void registerEntity(EntityDescriptor entity, String contextUrl) {
    entityMap.put(entity, contextUrl);
    registerContextUrl(contextUrl);
  }

  public void registerServlet(String url, HttpServlet servlet)
      throws ServletException {
    registerServlet(url, findContextUrl(url), servlet,
        (servlet instanceof GettableHttpServlet),
        (servlet instanceof PostableHttpServlet));
  }

  private String findContextUrl(String urlString) {
    URL url = HttpUtil.parseUrlString(urlString);
    if (url == null) {
      return null;
    }
    while (true) {
      url = HttpUtil.parentUrl(url);
      if (url == null) {
        return null;
      }
      String us = url.toString();
      if (contextMap.containsKey(us)) {
        return us;
      }
    }
  }

  public void registerServlet(URL url, HttpServlet servlet)
      throws ServletException {
    registerServlet(url.toString(), servlet);
  }

  public void registerServlet(Endpoint endpoint, HttpServlet servlet)
      throws ServletException {
    EntityDescriptor entity = findEnclosingEntity(endpoint);
    String contextUrl = entityMap.get(entity);
    registerServlet(endpoint.getLocation(), contextUrl, servlet,
        (servlet instanceof GettableHttpServlet),
        (servlet instanceof PostableHttpServlet));
  }

  private static EntityDescriptor findEnclosingEntity(Endpoint endpoint) {
    XMLObject o = endpoint;
    while (true) {
      o = o.getParent();
      if (o == null) { return null; }
      if (o instanceof EntityDescriptor) { return (EntityDescriptor) o; }
    }
  }

  public void registerServlet(String url, HttpServlet servlet, ServletCapabilities c)
      throws ServletException {
    boolean isGettable = false;
    boolean isPostable = false;
    switch (c) {
      case GETTABLE:
        isGettable = true;
        break;
      case POSTABLE:
        isPostable = true;
        break;
      case GETTABLE_AND_POSTABLE:
        isGettable = true;
        isPostable = true;
        break;
    }
    registerServlet(url, findContextUrl(url), servlet, isGettable, isPostable);
  }

  private void registerServlet(String url, String contextUrl, HttpServlet servlet,
      boolean isGettable, boolean isPostable)
      throws ServletException {
    url = canonicalUrl(url);
    logger.info("Registering servlet for URL: " + url);
    servlet.init(new MockServletConfig(getServletContext(contextUrl)));
    if (isGettable) { getMap.put(url, servlet); }
    if (isPostable) { postMap.put(url, servlet); }
  }

  private MockServletContext getServletContext(String contextUrl) {
    MockServletContext context = (contextUrl != null) ? contextMap.get(contextUrl) : null;
    return (context != null) ? context : new MockServletContext();
  }

  public void resetServletContexts() {
    for (String contextUrl : contextMap.keySet()) {
      contextMap.put(contextUrl, new MockServletContext());
    }
  }

  public void registerRequestAction(Class<? extends HttpServlet> servletClass,
      RequestAction action) {
    requestActions.put(servletClass, action);
  }

  public void unregisterRequestAction(Class<? extends HttpServlet> servletClass,
      RequestAction action) {
    requestActions.remove(servletClass, action);
  }

  public void registerResponseAction(Class<? extends HttpServlet> servletClass,
      ResponseAction action) {
    responseActions.put(servletClass, action);
  }

  public void unregisterResponseAction(Class<? extends HttpServlet> servletClass,
      ResponseAction action) {
    responseActions.remove(servletClass, action);
  }

  /**
   * Register a URL alias.
   *
   * When an HTTP request is sent to an alias, it is automatically "redirected"
   * to a replacement URL, and the request's URL is modified as well.  If the
   * original request URL contains a query, that is preserved.
   *
   * @param alias The alias URL.
   * @param replacement The replacement URL to redirect to.
   */
  public void registerUrlAlias(String alias, String replacement) {
    urlAliases.put(alias, replacement);
  }

  public void reset() {
    getMap.clear();
    postMap.clear();
    contextMap.clear();
    entityMap.clear();
    urlAliases.clear();
    resetExchangeLog();
    requestActions.clear();
    responseActions.clear();
  }

  @Override
  public void exchange(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    ExchangeLog exchangeLog = exchangeLogBuilder.push();
    String method = request.getMethod();
    if (HttpUtil.isHttpGetMethod(method) || HttpUtil.isHttpHeadMethod(method)) {
      exchangeLog.setMethod(ExchangeLog.Method.GET);
      doGet(request, response, exchangeLog);
    } else if (HttpUtil.isHttpPostMethod(method)) {
      exchangeLog.setMethod(ExchangeLog.Method.POST);
      doPost(request, response, exchangeLog);
    } else {
      throw new ServletException("Unsupported request method: " + method);
    }
    exchangeLogBuilder.pop(exchangeLog);
  }

  private void doGet(HttpServletRequest request, HttpServletResponse response,
      ExchangeLog exchangeLog)
      throws ServletException, IOException {
    HttpServlet servlet = getServlet(request, getMap);
    logRequest(servlet, "doGet", request);
    exchangeLog.setServletName(servlet.getClass().getSimpleName());
    for (RequestAction action : requestActions.get(servlet.getClass())) {
      action.apply(request);
    }
    try {
      if (servlet instanceof GettableHttpServlet) {
        GettableHttpServlet.class.cast(servlet).doGet(request, response);
      } else {
        callDoGetByReflection(servlet, request, response);
      }
    } catch (IOException e) {
      throw e;
    } catch (Exception e) {
      logger.log(Level.WARNING, "Exception from servlet: ", e);
      if (response.isCommitted()) {
        throw new ServletException(e);
      }
      ServletBase.initErrorResponse(response,
          HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
    logResponse(servlet, "doGet", response);
    exchangeLog.updateFromResponse(response);
    for (ResponseAction action : responseActions.get(servlet.getClass())) {
      action.apply(response);
    }
  }

  private void doPost(HttpServletRequest request, HttpServletResponse response,
      ExchangeLog exchangeLog)
      throws ServletException, IOException {
    HttpServlet servlet = getServlet(request, postMap);
    logRequest(servlet, "doPost", request);
    exchangeLog.setServletName(servlet.getClass().getSimpleName());
    for (RequestAction action : requestActions.get(servlet.getClass())) {
      action.apply(request);
    }
    try {
      if (servlet instanceof PostableHttpServlet) {
        PostableHttpServlet.class.cast(servlet).doPost(request, response);
      } else {
        callDoPostByReflection(servlet, request, response);
      }
    } catch (Exception e) {
      if (response.isCommitted()) {
        throw new ServletException(e);
      }
      ServletBase.initErrorResponse(response,
          HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    }
    logResponse(servlet, "doPost", response);
    exchangeLog.updateFromResponse(response);
    for (ResponseAction action : responseActions.get(servlet.getClass())) {
      action.apply(response);
    }
  }

  private HttpServlet getServlet(
      HttpServletRequest request, Map<String, HttpServlet> methodMap)
      throws ServletException, IOException {
    String url = requestUrl(request);
    HttpServlet servlet = methodMap.get(url);
    if (servlet == null) {
      logger.severe("Unknown request URL: " + url);
      throw new ServletException("Unknown request URL: " + url);
    }
    // Make sure that the request has an appropriate context path.
    String contextUrl = findContextUrl(url);
    if (contextUrl != null) {
      MockHttpServletRequest.class.cast(request)
          .setContextPath((new URL(contextUrl)).getPath());
    }
    return servlet;
  }

  private String canonicalUrl(String urlString) {
    return HttpUtil.stripQueryFromUrl(HttpUtil.urlFromString(urlString)).toString();
  }

  private String requestUrl(HttpServletRequest request) {
    URL url = HttpUtil.getRequestUrl(request, true);
    String key = HttpUtil.stripQueryFromUrl(url).toString();
    String replacement = urlAliases.get(key);
    if (replacement == null) {
      return key;
    }
    // Edit the request to refer to the replacement rather than the original URL.
    URL replacementUrl
        = HttpUtil.mergeQueryIntoUrl(HttpUtil.urlFromString(replacement), url.getQuery());
    MockHttpServletRequest mr = MockHttpServletRequest.class.cast(request);
    mr.setServerName(replacementUrl.getHost());
    int port = replacementUrl.getPort();
    if (port >= 0) {
      mr.setServerPort(port);
    }
    mr.setRequestURI(replacementUrl.getFile());
    return replacement;
  }

  private void logRequest(HttpServlet servlet, String methodName, HttpServletRequest request)
      throws IOException {
    if (logMessages) {
      logger.logp(Level.INFO, servlet.getClass().getName(), methodName,
          ServletTestUtil.servletRequestToString(request, "Request"));
    }
  }

  private void logResponse(HttpServlet servlet, String methodName, HttpServletResponse response)
      throws IOException {
    if (logMessages) {
      logger.logp(Level.INFO, servlet.getClass().getName(), methodName,
          ServletTestUtil.servletResponseToString(
              (MockHttpServletResponse) response, "Response"));
    }
  }

  static Method doGet = null;
  static Method doPost = null;

  static {
    Class<?>[] argClasses =
        {HttpServletRequest.class, HttpServletResponse.class};
    doGet = null;
    try {
      doGet = HttpServlet.class.getDeclaredMethod("doGet", argClasses);
    } catch (SecurityException e) {
      e.printStackTrace();
    } catch (NoSuchMethodException e) {
      e.printStackTrace();
    }
    doGet.setAccessible(true);
    logger.info("doGet method found");
    try {
      doPost = HttpServlet.class.getDeclaredMethod("doPost", argClasses);
    } catch (SecurityException e) {
      e.printStackTrace();
    } catch (NoSuchMethodException e) {
      e.printStackTrace();
    }
    doPost.setAccessible(true);
    logger.info("doPost method found");
  }

  private void callDoPostByReflection(HttpServlet servlet,
      HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    callServletActionByReflection(doPost, servlet, request, response);
  }

  private void callDoGetByReflection(HttpServlet servlet,
      HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    callServletActionByReflection(doGet, servlet, request, response);
  }

  private void callServletActionByReflection(Method m, HttpServlet servlet,
      HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    Object[] args = {request, response};
    try {
      m.invoke(servlet, args);
    } catch (IllegalArgumentException e) {
      e.printStackTrace();
      throw new IllegalStateException();
    } catch (IllegalAccessException e) {
      e.printStackTrace();
      throw new IllegalStateException();
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (cause instanceof ServletException) {
        e.printStackTrace();
        throw ServletException.class.cast(cause);
      }
      if (cause instanceof IOException) {
        e.printStackTrace();
        throw IOException.class.cast(cause);
      }
      throw new IllegalStateException(e);
    }
  }

  public void resetExchangeLog() {
    exchangeLogBuilder.reset();
  }

  public List<ExchangeLog> getExchangeLogs() {
    return exchangeLogBuilder.getExchangeLogs();
  }
}
