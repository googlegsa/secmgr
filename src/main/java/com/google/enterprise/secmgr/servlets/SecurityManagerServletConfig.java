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

package com.google.enterprise.secmgr.servlets;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.authncontroller.AuthnGuiceModule;
import com.google.enterprise.secmgr.authncontroller.AuthnModule;
import com.google.enterprise.secmgr.authzcontroller.AuthorizationMapManagerImpl;
import com.google.enterprise.secmgr.authzcontroller.AuthzGuiceModule;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.common.GCookie;
import com.google.enterprise.secmgr.common.SecurityManagerUtil;
import com.google.enterprise.secmgr.config.AuthzMechanism;
import com.google.enterprise.secmgr.config.ConfigModule;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.docfetchercontroller.DocFetcherGuiceModule;
import com.google.enterprise.secmgr.http.HttpClientModule;
import com.google.enterprise.secmgr.identity.CredentialModule;
import com.google.enterprise.secmgr.modules.AuthzCacheModule;
import com.google.enterprise.secmgr.modules.AuthzModule;
import com.google.enterprise.secmgr.modules.CertificateCredentialsGatherer;
import com.google.enterprise.secmgr.modules.ConnectorModule;
import com.google.enterprise.secmgr.modules.DenyAuthzModule;
import com.google.enterprise.secmgr.modules.FormModule;
import com.google.enterprise.secmgr.modules.GroupsUpdateModule;
import com.google.enterprise.secmgr.modules.HttpBasicModule;
import com.google.enterprise.secmgr.modules.HttpRequestModule;
import com.google.enterprise.secmgr.modules.KerberosCredentialsGatherer;
import com.google.enterprise.secmgr.modules.LdapModule;
import com.google.enterprise.secmgr.modules.ModulesGuiceModule;
import com.google.enterprise.secmgr.modules.NtlmModule;
import com.google.enterprise.secmgr.modules.PerUrlAclModule;
import com.google.enterprise.secmgr.modules.PolicyAclsModule;
import com.google.enterprise.secmgr.modules.PreauthenticatedModule;
import com.google.enterprise.secmgr.modules.RedirectCredentialsGatherer;
import com.google.enterprise.secmgr.modules.SamlCredentialsGatherer;
import com.google.enterprise.secmgr.modules.SamlModule;
import com.google.enterprise.secmgr.modules.SampleUrlModule;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.sessionmanager.ArtifactStorageService;
import com.google.enterprise.sessionmanager.SessionFilter;
import com.google.gson.GsonBuilder;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.servlet.GuiceServletContextListener;
import com.google.inject.servlet.ServletModule;
import java.io.File;
import java.util.Map;
import java.util.logging.Logger;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.http.HttpServlet;

/**
 * This is the top-level configuration of the security manager.  All the Guice
 * injection starts here.
 */
public class SecurityManagerServletConfig extends GuiceServletContextListener {
  private static final Logger logger = Logger.getLogger(
      SecurityManagerServletConfig.class.getName());

  private static ServletContext servletContext = null;

  private static Injector injector = null;
  private static final Map<String, Class<? extends HttpServlet>> SERVLETS;
  static {
    ImmutableMap.Builder<String, Class<? extends HttpServlet>> builder = ImmutableMap.builder();
    builder.put("/samlauthn", SamlAuthn.class);
    builder.put("/samlartifact", SamlArtifactResolve.class);
    builder.put("/samlauthz", SamlAuthz.class);
    builder.put("/samlassertionconsumer", SamlAssertionConsumer.class);
    builder.put("/testConnectivity", HelloWorld.class);
    builder.put("/commands", CommandsServlet.class);
    builder.put("/fetchDocument", DocumentFetcher.class);
    builder.put("/authenticate", AuthnServlet.class);
    builder.put("/authorize", AuthzServlet.class);
    SERVLETS = builder.build();
  }

  @Override
  public void contextInitialized(ServletContextEvent servletContextEvent) {
    servletContext = servletContextEvent.getServletContext();
    FileUtil.setContextDirectory(servletContext.getRealPath("/WEB-INF"));
    super.contextInitialized(servletContextEvent);
    initializeGson();
    SecurityManagerUtil.initLogClientFlags();
    logger.info("Context inited " + servletContext.getRealPath("/WEB-INF"));
    init();
  }

  @Override
  protected synchronized Injector getInjector() {
    if (injector != null) {
      return injector;
    }

    String configPath = getConfigPath();
    injector =  makeInjector(configPath, new LocalServletModule());
    return injector;
  }

  private String getConfigPath() {
    String configPathProp = "configPath";
    // search in Java system params (specified -DconfigPath=...)
    String path = System.getProperty(configPathProp);
    if (!Strings.isNullOrEmpty(path)) {
      return path.trim();
    }
    /*
    search in web-app configuration, e.g. in your-ctx.xml in conf/Catalina/localhost/your-ctx.xml
    <Context docBase="/root/security-manager.war">
      <Parameter name="configPath" value="/root/AuthSites2.json"
             override="false"/>
    </Context>
    */
    path = servletContext.getInitParameter(configPathProp);
    if (!Strings.isNullOrEmpty(path)) {
      return path.trim();
    }
    if (new File(FileUtil.getContextDirectory(), "conf/AuthSites.json").exists()) {
      return "conf/AuthSites.json"; // sample config for open source installation
    }
    return "../../../../conf/AuthSites.json"; // GSA installation
  }

  @VisibleForTesting
  public static synchronized Injector makeTestingInjector(String configFile) {
    injector = makeInjector(configFile, new TestModule());
    init();
    return injector;
  }

  private static Injector makeInjector(String configFile, AbstractModule... extra) {
    ImmutableList.Builder<AbstractModule> guiceModuleBuilder = ImmutableList.builder();
    guiceModuleBuilder.add(new ConfigModule(configFile));
    guiceModuleBuilder.add(new AuthnGuiceModule());
    guiceModuleBuilder.add(new AuthzGuiceModule());
    guiceModuleBuilder.add(new HttpClientModule());
    guiceModuleBuilder.add(new DocFetcherGuiceModule());
    guiceModuleBuilder.add(new ModulesGuiceModule());
    for (AbstractModule module : extra) {
      guiceModuleBuilder.add(module);
    }
    return Guice.createInjector(guiceModuleBuilder.build());
  }

  private static void init() {
    AuthnController authnController = injector.getInstance(AuthnController.class);
    authnController.setCredentialsGatherers(
        ImmutableSet.of(
            injector.getInstance(CertificateCredentialsGatherer.class),
            injector.getInstance(KerberosCredentialsGatherer.class),
            injector.getInstance(RedirectCredentialsGatherer.class),
            injector.getInstance(SamlCredentialsGatherer.class)));
    authnController.setModules(
        ImmutableSet.<AuthnModule>of(
            injector.getInstance(ConnectorModule.class),
            injector.getInstance(FormModule.class),
            injector.getInstance(HttpBasicModule.class),
            injector.getInstance(LdapModule.class),
            injector.getInstance(GroupsUpdateModule.class),
            injector.getInstance(NtlmModule.class),
            injector.getInstance(PreauthenticatedModule.class),
            injector.getInstance(SampleUrlModule.class)));

    AuthorizationMapManagerImpl authzMap
        = injector.getInstance(AuthorizationMapManagerImpl.class);
    ImmutableMap.Builder<AuthzMechanism, AuthzModule> authzModulesBuilder = ImmutableMap.builder();
    authzMap.setModules(authzModulesBuilder
        .put(AuthzMechanism.CACHE, injector.getInstance(AuthzCacheModule.class))
        .put(AuthzMechanism.CONNECTOR, injector.getInstance(ConnectorModule.class))
        .put(AuthzMechanism.DENY, injector.getInstance(DenyAuthzModule.class))
        .put(AuthzMechanism.HEADREQUEST, injector.getInstance(HttpRequestModule.class))
        .put(AuthzMechanism.POLICY, injector.getInstance(PolicyAclsModule.class))
        .put(AuthzMechanism.SAML, injector.getInstance(SamlModule.class))
        .put(AuthzMechanism.PER_URL_ACL, injector.getInstance(PerUrlAclModule.class))
        .build());

    OpenSamlUtil.setArtifactStorageService(injector.getInstance(ArtifactStorageService.class));
  }

  private static final class LocalServletModule extends ServletModule {

    @Override
    protected void configureServlets() {
      for (Map.Entry<String, Class<? extends HttpServlet>> entry : SERVLETS.entrySet()) {
        serve(entry.getKey()).with(entry.getValue());
      }
      filter("/*").through(SessionFilter.class);
    }
  }

  private static final class TestModule extends AbstractModule {

    @Override
    protected void configure() {
      for (Class<? extends HttpServlet> clazz : SERVLETS.values()) {
        bind(clazz);
      }
    }
  }

  @VisibleForTesting
  public static void initializeGson() {
    ConfigSingleton.setGsonRegistrations(
        new ConfigSingleton.GsonRegistrations() {
          @Override
          public void register(GsonBuilder builder) {
            ConfigModule.registerTypeAdapters(builder);
            AuthnGuiceModule.registerTypeAdapters(builder);
            CredentialModule.registerTypeAdapters(builder);
            GCookie.registerTypeAdapters(builder);
          }
        });
  }
}
