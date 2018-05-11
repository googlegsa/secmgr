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

import com.google.common.annotations.VisibleForTesting;
import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.inject.Singleton;
import com.google.inject.name.Named;

import java.util.Collection;
import java.util.logging.Logger;

import javax.inject.Inject;

/**
 * An authorization module for the authorization cache.
 */
@Singleton
public final class AuthzCacheModule implements AuthzModule {
  private static final Logger logger = Logger.getLogger(AuthzCacheModule.class.getName());

  private final AuthzCache cache;

  @VisibleForTesting
  @Inject
  AuthzCacheModule(@Named("UserCacheConnector.cacheExpirySeconds") Integer cacheExpirySeconds) {
    cache = new AuthzCache(cacheExpirySeconds);
    logger.info("UserCache constructed; entries expire after " + cacheExpirySeconds + " seconds");
  }

  @Override
  public AuthzResult authorize(Collection<Resource> resources, SessionView view,
      FlexAuthzRule rule) {
    String sessionId = view.getSessionId();
    Collection<String> urls = Resource.resourcesToUrls(resources);
    AuthzResult.Builder builder = AuthzResult.builder(urls);
    for (String url : urls) {
      AuthzStatus status = cache.lookup(sessionId, url);
      builder.putStatusFromCache(url, (status != null) ? status : AuthzStatus.INDETERMINATE);
    }
    return builder.build();
  }

  public void rememberPermit(String resourceUrl, String sessionId) {
    cache.addEntry(sessionId, resourceUrl, AuthzStatus.PERMIT);
  }

  public void rememberDeny(String resourceUrl, String sessionId) {
    cache.addEntry(sessionId, resourceUrl, AuthzStatus.DENY);
  }

  public void clearCache() {
    cache.clear();
  }
}
