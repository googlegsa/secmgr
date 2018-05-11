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

package com.google.enterprise.secmgr.authzcontroller;

import com.google.inject.AbstractModule;
import com.google.inject.assistedinject.FactoryModuleBuilder;

/**
 * Guice configuration for this package.
 */
public final class AuthzGuiceModule extends AbstractModule {

  @Override
  protected void configure() {
    bind(AuthorizationController.class).to(AuthorizationControllerImpl.class);
    bind(AuthorizationDispatcher.class).to(ParallelAuthorizationDispatcher.class);
    bind(AuthorizationMapManager.class).to(AuthorizationMapManagerImpl.class);
    bind(Authorizer.class).to(AuthorizerImpl.class);
    install(new FactoryModuleBuilder()
        .implement(AuthorizationMethod.class, AuthorizationMethodImpl.class)
        .build(AuthorizationMethodFactory.class));
  }
}
