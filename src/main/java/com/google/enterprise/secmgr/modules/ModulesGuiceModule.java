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

import com.google.inject.AbstractModule;
import com.google.inject.name.Names;

/**
 * Guice configuration for this package.
 */
public final class ModulesGuiceModule extends AbstractModule {

  @Override
  protected void configure() {
    bind(AuthzCacheModule.class);
    bind(CertificateCredentialsGatherer.class);
    bind(ConnectorModule.class);
    bind(FormModule.class);
    bind(HttpBasicModule.class);
    bind(HttpRequestModule.class);
    bind(KerberosCredentialsGatherer.class);
    bind(LdapModule.class);
    bind(GroupsUpdateModule.class);
    bind(NtlmModule.class);
    bind(PreauthenticatedModule.class);
    bind(PolicyAclsModule.class);
    bind(RedirectCredentialsGatherer.class);
    bind(SamlCredentialsGatherer.class);
    bind(SamlModule.class);
    bind(SampleUrlModule.class);
    bind(PerUrlAclModule.class);

    bind(Long.class)
        .annotatedWith(Names.named("PolicyConnector.dataReloadPeriodMillis"))
        .toInstance(Long.valueOf(30 * 1000));  // 30 seconds
    bind(Integer.class)
        .annotatedWith(Names.named("UserCacheConnector.cacheExpirySeconds"))
        .toInstance(Integer.valueOf(60 * 60));  // one hour
  }
}
