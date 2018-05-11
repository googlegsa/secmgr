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

import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.inject.Singleton;

import java.util.Collection;
import java.util.logging.Logger;

import javax.annotation.concurrent.Immutable;
import javax.inject.Inject;

/**
 * Simple authorization module that denies access to all resources.
 */
@Singleton
@Immutable
public final class DenyAuthzModule implements AuthzModule {
  private static final Logger logger = Logger.getLogger(DenyAuthzModule.class.getName());

  @Inject
  private DenyAuthzModule() {
  }

  @Override
  public AuthzResult authorize(Collection<Resource> resources, SessionView view,
      FlexAuthzRule rule) {
    Collection<String> urls = Resource.resourcesToUrls(resources);
    AuthzResult.Builder builder = AuthzResult.builder(urls);
    for (String url : urls) {
      logger.info(view.logMessage("Status of resource %s is %s", url, AuthzStatus.DENY));
      builder.put(url, AuthzStatus.DENY);
    }
    return builder.build();
  }
}
