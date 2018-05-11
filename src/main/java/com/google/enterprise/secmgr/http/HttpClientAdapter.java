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

package com.google.enterprise.secmgr.http;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableListMultimap;
import com.google.common.collect.Iterables;
import com.google.common.collect.ListMultimap;
import com.google.common.collect.MultimapBuilder;
import com.google.common.io.ByteStreams;
import com.google.common.io.CharStreams;
import com.google.enterprise.secmgr.common.CookieStore;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.HttpUtil;
import com.google.enterprise.secmgr.common.ServletBase;
import com.google.enterprise.secmgr.ssl.ApacheSslSocketFactory;
import com.google.enterprise.secmgr.ssl.SslContextFactory;
import com.google.inject.Singleton;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;
import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.params.AuthPolicy;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.BasicClientConnectionManager;
import org.apache.http.impl.conn.PoolingClientConnectionManager;
import org.apache.http.impl.conn.ProxySelectorRoutePlanner;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.util.EntityUtils;

/** A real instance of HttpClientInterface, using the HttpClient library for transport. */
@Immutable
@Singleton
@ParametersAreNonnullByDefault
final class HttpClientAdapter implements HttpClientInterface {

  // How long it takes to establish a connection before we give up:
  private static int getConnectionTimeoutMillis() {
    String conto = System.getProperty("secmgr.http.ConnectionTimeoutMillis");
    if (conto == null || conto.isEmpty()) {
      return 3000;
    }
    return Integer.parseInt(conto);
  }

  // How long we wait for data to be sent or received over the underlying socket:
  private static int getSocketTimeoutMillis() {
    String soto = System.getProperty("secmgr.http.SocketTimeoutMillis");
    if (soto == null || soto.isEmpty()) {
      return 3000;
    }
    return Integer.parseInt(soto);
  }

  // How often we check for idle connections:
  private static int getIdleIntervalMillis() {
    String idle = System.getProperty("secmgr.http.IdleIntervalMillis");
    if (idle == null || idle.isEmpty()) {
      return 15000;
    }
    return Integer.parseInt(idle);
  }

  // How long a connection is unused before it is considered idle:
  private static int getIdleConnectionMillis() {
    String idle = System.getProperty("secmgr.http.IdleConnectionMillis");
    if (idle == null || idle.isEmpty()) {
      return 15000;
    }
    return Integer.parseInt(idle);
  }

  // The maximum number of simultaneous connections to a given host (and port):
  private static int getMaxConnectionsPerHostPort() {
    String maxcon = System.getProperty("secmgr.http.MaxConnectionsPerHost");
    if (maxcon == null || maxcon.isEmpty()) {
      return 4;
    }
    return Integer.parseInt(maxcon);
  }

  // The maximum number of simultaneous connections to a given host (and port):
  private static int getMaxConnectionsTotal() {
    String maxcon = System.getProperty("secmgr.http.MaxConnectionsTotal");
    if (maxcon == null || maxcon.isEmpty()) {
      return 40;
    }
    return Integer.parseInt(maxcon);
  }

  private static final long IDLE_INTERVAL_MILLIS = getIdleIntervalMillis();
  private static final long IDLE_CONNECTION_MILLIS = getIdleConnectionMillis();

  @Nonnull private final HttpClient httpClient;
  @Nonnull private DenyRulesInterface denyRules;
  @Nonnull private ProxyConfInterface proxyConf;
  @Nullable private IdleConnectionMonitorThread idleConnectionMonitor;

  @Inject
  private HttpClientAdapter(DenyRulesInterface denyRules, ProxyConfInterface proxyConf) {
    this(denyRules, proxyConf, buildPoolingClientConnectionManager());

    idleConnectionMonitor = new IdleConnectionMonitorThread(httpClient.getConnectionManager());
    idleConnectionMonitor.start();
  }

  private HttpClientAdapter(DenyRulesInterface denyRules, ProxyConfInterface proxyConf,
      ClientConnectionManager connectionManager) {
    this.denyRules = denyRules;
    this.proxyConf = proxyConf;

    ProxySelector proxySelector = new ConfigurableProxySelector(proxyConf);

    httpClient = new DefaultHttpClient(connectionManager);
    ProxySelectorRoutePlanner routePlanner = new ProxySelectorRoutePlanner(
        httpClient.getConnectionManager().getSchemeRegistry(),
        proxySelector);
    ((DefaultHttpClient) httpClient).setRoutePlanner(routePlanner);

    HttpParams params = httpClient.getParams();
    params.setParameter(ClientPNames.COOKIE_POLICY, CookiePolicy.IGNORE_COOKIES);
    params.setParameter(ClientPNames.HANDLE_AUTHENTICATION, false);
    params.setParameter(ClientPNames.HANDLE_REDIRECTS, false);
    params.setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, getConnectionTimeoutMillis());
    params.setParameter(CoreConnectionPNames.SO_TIMEOUT, getSocketTimeoutMillis());
    params.setParameter(CoreProtocolPNames.USER_AGENT, HttpUtil.USER_AGENT);
  }

  private static ClientConnectionManager buildPoolingClientConnectionManager() {
    PoolingClientConnectionManager connectionManager = new PoolingClientConnectionManager(
        buildSchemeRegistry());
    connectionManager.setDefaultMaxPerRoute(getMaxConnectionsPerHostPort());
    connectionManager.setMaxTotal(getMaxConnectionsTotal());
    return connectionManager;
  }

  private static SchemeRegistry buildSchemeRegistry() {
    SchemeRegistry schemeRegistry = new SchemeRegistry();
    schemeRegistry.register(new Scheme("http", 80, PlainSocketFactory.getSocketFactory()));
    schemeRegistry.register(
        new Scheme("https", 443,
            new ApacheSslSocketFactory(
                SslContextFactory.createContext(),
                ApacheSslSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)));
    return schemeRegistry;
  }

  @Override
  protected void finalize() throws Throwable {
    try {
      if (idleConnectionMonitor != null) {
        idleConnectionMonitor.shutdown();
      }
    } finally {
      super.finalize();
    }
  }

  @VisibleForTesting
  protected void setDenyRules(DenyRulesInterface denyRules) {
    this.denyRules = denyRules;
  }

  @ThreadSafe
  public static class IdleConnectionMonitorThread extends Thread {
    private final ClientConnectionManager connectionManager;
    private volatile boolean shutdown;

    public IdleConnectionMonitorThread(ClientConnectionManager connectionManager) {
      super();
      this.connectionManager = connectionManager;
      setDaemon(true);
    }

    @Override
    public void run() {
      try {
        while (!shutdown) {
          synchronized (this) {
            wait(IDLE_INTERVAL_MILLIS);
            connectionManager.closeExpiredConnections();
            connectionManager.closeIdleConnections(IDLE_CONNECTION_MILLIS, TimeUnit.MILLISECONDS);
          }
        }
      } catch (InterruptedException ex) {
        // done
      }
    }

    public void shutdown() {
      shutdown = true;
      synchronized (this) {
        notifyAll();
      }
    }

    public boolean isRunning() {
      return !shutdown;
    }
  }

  @VisibleForTesting
  int getMaxConnectionsPerHost() {
    return getMaxConnectionsPerHostPort();
  }

  @Override
  public HttpExchange headExchange(URL url) {
    return new ClientExchange(httpClient, new HttpHead(HttpUtil.toUri(url)), null);
  }

  @Override
  public HttpExchange getExchange(URL url) {
    return new ClientExchange(httpClient, new HttpGet(HttpUtil.toUri(url)), null);
  }

  @Override
  public HttpExchange getExchange(URL url, int length) {
    Preconditions.checkArgument(length >= 0);
    HttpExchange exchange = getExchange(url);
    exchange.setRequestHeader(HttpUtil.HTTP_HEADER_RANGE, HttpUtil.getRangeString(length));
    return exchange;
  }

  @Override
  public HttpExchange getExchange(URL url, HttpExchangeContext context) {
    return new ClientExchange(httpClient, new HttpGet(HttpUtil.toUri(url)), context, null);
  }

  @Override
  public HttpExchange postExchange(URL url, @Nullable ListMultimap<String, String> parameters) {
    return new ClientExchange(httpClient, new HttpPost(HttpUtil.toUri(url)), parameters);
  }

  @Override
  public HttpExchange newHttpExchange(URL url) {
    DenyRule rule = denyRules.getRule(url.toString());
    if (rule == null) {
      return headExchange(url);
    }
    if (rule.getRequestType() == DenyRule.TYPE.HEAD) {
      return headExchange(url);
    }
    if (rule.getRequestType() == DenyRule.TYPE.GET) {
      if (rule.getLength() < 0) {
        // if the rule's length is < 0, treat it as a full GET
        return getExchange(url);
      }
      return getExchange(url, rule.getLength());
    }
    throw new IllegalStateException("Unknown request type: " + rule.getRequestType());
  }

  // TODO: Make this static (or better to create a Builder)
  @Override
  public HttpClientInterface newSingleUseInstance() {
    return new HttpClientAdapter(denyRules, proxyConf,
        new BasicClientConnectionManager(buildSchemeRegistry()));
  }

  @NotThreadSafe
  @ParametersAreNonnullByDefault
  private static final class ClientExchange implements HttpExchange {

    @Nonnull final HttpClient httpClient;
    @Nonnull final HttpUriRequest request;
    @Nullable final ListMultimap<String, String> parameters;
    @Nonnull final URI uri;
    @Nonnull final BasicHttpContext localContext;
    @Nonnull final CookieStore exchangeCookies;
    boolean followRedirects;
    @Nullable HttpResponse response;

    // TODO: refactor these constructors with a Builder
    ClientExchange(HttpClient httpClient, HttpUriRequest request,
        @Nullable ListMultimap<String, String> parameters) {
      this(httpClient, request, null, parameters);
    }

    ClientExchange(HttpClient httpClient, HttpUriRequest request,
        @Nullable HttpExchangeContext context, @Nullable ListMultimap<String, String> parameters) {
      this.httpClient = httpClient;
      this.request = request;
      this.parameters =
          (parameters != null)
              ? MultimapBuilder.hashKeys().arrayListValues().build(parameters)
              : null;
      uri = request.getURI();
      if (context != null && context instanceof BasicHttpExchangeContext) {
        this.localContext = ((BasicHttpExchangeContext) context).getContext();
      } else {
        this.localContext = new BasicHttpContext();
      }
      exchangeCookies = GCookie.makeStore();
      followRedirects = false;
    }

    @Override
    public void setBasicAuthCredentials(String username, String password) {
      Preconditions.checkArgument(!Strings.isNullOrEmpty(username));
      Preconditions.checkArgument(!Strings.isNullOrEmpty(password));

      CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
      credentialsProvider.setCredentials(
          new AuthScope(uri.getHost(), uri.getPort(), AuthScope.ANY_REALM, AuthPolicy.BASIC),
          new UsernamePasswordCredentials(username, password));
      localContext.setAttribute(ClientContext.CREDS_PROVIDER, credentialsProvider);

      AuthCache authCache = new BasicAuthCache();
      authCache.put(new HttpHost(uri.getHost(), uri.getPort(), uri.getScheme()), new BasicScheme());
      localContext.setAttribute(ClientContext.AUTH_CACHE, authCache);
    }

    @Override
    public void setFollowRedirects(boolean followRedirects) {
      this.followRedirects = followRedirects;
    }

    @Override
    public void setTimeout(int timeout) {
      HttpParams params = request.getParams();
      if (timeout > 0) {
        params.setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, timeout);
        params.setParameter(CoreConnectionPNames.SO_TIMEOUT, timeout);
      } else {
        params.setParameter(CoreConnectionPNames.CONNECTION_TIMEOUT, getConnectionTimeoutMillis());
        params.setParameter(CoreConnectionPNames.SO_TIMEOUT, getSocketTimeoutMillis());
      }
    }

    @Override
    public String getHttpMethod() {
      return request.getMethod();
    }

    @Override
    public URL getUrl() {
      return HttpUtil.toUrl(uri);
    }

    @Override
    public void addParameter(String name, String value) {
      Preconditions.checkArgument(!Strings.isNullOrEmpty(name));
      Preconditions.checkNotNull(value);
      Preconditions.checkState(parameters != null);
      parameters.put(name, value);
    }

    @Override
    public void setRequestHeader(String name, String value) {
      Preconditions.checkArgument(!Strings.isNullOrEmpty(name));
      Preconditions.checkNotNull(value);
      if (HttpUtil.HTTP_HEADER_COOKIE.equalsIgnoreCase(name)) {
        throw new IllegalArgumentException("setRequestHeader cannot be used for cookies.");
      }
      request.setHeader(name, value);
    }

    @Override
    public List<String> getRequestHeaderValues(String headerName) {
      Preconditions.checkArgument(!Strings.isNullOrEmpty(headerName));
      Header[] headers = request.getHeaders(headerName);
      ImmutableList.Builder<String> builder = ImmutableList.builder();
      for (Header header : headers) {
        builder.add(header.getValue());
      }
      return builder.build();
    }

    @Override
    public String getRequestHeaderValue(String headerName) {
      Preconditions.checkArgument(!Strings.isNullOrEmpty(headerName));
      Header[] headers = request.getHeaders(headerName);
      return (headers.length > 0)
          ? headers[0].getValue()
          : null;
    }

    @Override
    public void addCookies(Iterable<GCookie> cookies) {
      for (GCookie cookie : cookies) {
        exchangeCookies.add(cookie);
      }
    }

    @Override
    @Nonnull
    public CookieStore getCookies() {
      exchangeCookies.expireCookies();
      return exchangeCookies;
    }

    @Override
    public void setRequestBody(byte[] byteArrayRequestEntity) {
      Preconditions.checkNotNull(byteArrayRequestEntity);
      Preconditions.checkState(request instanceof HttpEntityEnclosingRequest && parameters == null);
      ((HttpEntityEnclosingRequest) request).setEntity(new ByteArrayEntity(byteArrayRequestEntity));
    }

    @Override
    public int exchange() throws IOException {
      exchange1(request);
      if (followRedirects) {
        while (ServletBase.isRedirectStatus(response.getStatusLine().getStatusCode())) {
          String location = getResponseHeaderValue(response, HttpUtil.HTTP_HEADER_LOCATION);
          HttpGet newRequest = new HttpGet(URI.create(location));
          exchange1(newRequest);
        }
      }
      return response.getStatusLine().getStatusCode();
    }

    void exchange1(HttpUriRequest request)
        throws IOException {

      // Compute the set of cookies to be sent.
      CookieStore toSend = GCookie.makeStore();
      for (GCookie cookie : getCookies()) {
        if (cookie.isGoodFor(request.getURI())) {
          toSend.add(cookie);
        }
      }

      // Convert those cookies to a header in the request.
      if (!toSend.isEmpty()) {
        request.setHeader(HttpUtil.HTTP_HEADER_COOKIE,
            GCookie.requestHeaderString(toSend, true));
      }

      // Initialize entity from parameters.
      if (parameters != null) {
        ((HttpEntityEnclosingRequest) request).setEntity(
            new UrlEncodedFormEntity(transformPostParameters(), "UTF-8"));
      }

      response = httpClient.execute(request, localContext);

      // Save the response cookies.
      GCookie.parseResponseHeaders(
          getResponseHeaderValues(response, HttpUtil.HTTP_HEADER_SET_COOKIE),
          uri,
          exchangeCookies);
    }

    List<NameValuePair> transformPostParameters() {
      return ImmutableList.copyOf(
          Iterables.transform(parameters.entries(),
              new Function<Map.Entry<String, String>, NameValuePair>() {
                @Override
                public NameValuePair apply(Map.Entry<String, String> entry) {
                  return new BasicNameValuePair(entry.getKey(), entry.getValue());
                }
              }));
    }

    HttpResponse getResponse() {
      Preconditions.checkState(response != null);
      return response;
    }

    @Override
    public int getStatusCode() {
      return getResponse().getStatusLine().getStatusCode();
    }

    @Override
    public ListMultimap<String, String> getResponseHeaders() {
      ImmutableListMultimap.Builder<String, String> builder = ImmutableListMultimap.builder();
      for (Header header : getResponse().getAllHeaders()) {
        builder.put(header.getName().toLowerCase(), header.getValue());
      }
      return builder.build();
    }

    @Override
    public List<String> getResponseHeaderValues(String name) {
      Preconditions.checkArgument(!Strings.isNullOrEmpty(name));
      return getResponseHeaderValues(response, name);
    }

    List<String> getResponseHeaderValues(HttpResponse response, String name) {
      ImmutableList.Builder<String> builder = ImmutableList.builder();
      for (Header header : response.getHeaders(name)) {
        builder.add(header.getValue());
      }
      return builder.build();
    }

    @Override
    public String getResponseHeaderValue(String name) {
      Preconditions.checkArgument(!Strings.isNullOrEmpty(name));
      return getResponseHeaderValue(response, name);
    }

    String getResponseHeaderValue(HttpResponse response, String name) {
      Header header = response.getFirstHeader(name);
      return (header != null) ? header.getValue() : null;
    }

    @Override
    public String getResponseCharSet() {
      HttpEntity responseEntity = getResponse().getEntity();
      if (responseEntity != null) {
        Header header = responseEntity.getContentType();
        if (header != null) {
          HeaderElement[] elements = header.getElements();
          if (elements.length == 1) {
            NameValuePair param = elements[0].getParameterByName("charset");
            if (param != null) {
              return param.getValue();
            }
          }
        }
      }

      // the interface declares this method as returning a non-null value, and getParameter
      // can return null here.
      String responseCharSet = (String)
          getResponse().getParams().getParameter(CoreProtocolPNames.HTTP_CONTENT_CHARSET);
      return responseCharSet == null ? UTF_8.name() : responseCharSet;

    }

    @Override
    public InputStream getResponseEntityAsStream()
        throws IOException {
      HttpEntity responseEntity = getResponse().getEntity();

      if (responseEntity == null) {
        // if responseEntity is null, return a 0-length response
        return new ByteArrayInputStream(new byte[0]);
      }

      return responseEntity.getContent();

    }

    @Override
    public byte[] getResponseEntityAsByteArray()
        throws IOException {
      InputStream stream = getResponseEntityAsStream();
      try {
        return ByteStreams.toByteArray(stream);
      } finally {
        stream.close();
      }
    }

    @Override
    public String getResponseEntityAsString()
        throws IOException {
      InputStream stream = getResponseEntityAsStream();
      try {
        return CharStreams.toString(new InputStreamReader(stream, getResponseCharSet()));
      } finally {
        stream.close();
      }
    }

    @Override
    public void close() {
      if (response != null) {
        try {
          EntityUtils.consume(response.getEntity());
        } catch (IOException e) {
          // ignore
        }
      }
    }
  }
}
