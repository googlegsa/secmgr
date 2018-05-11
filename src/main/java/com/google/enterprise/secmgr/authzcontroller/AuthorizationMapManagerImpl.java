// Copyright 2009 Google Inc.
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

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.enterprise.secmgr.common.Stringify;
import com.google.enterprise.secmgr.config.AuthzMechanism;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.FlexAuthorizer;
import com.google.enterprise.secmgr.config.FlexAuthzRoutingTableEntry;
import com.google.enterprise.secmgr.config.FlexAuthzRule;
import com.google.enterprise.secmgr.modules.AuthzModule;
import com.google.inject.Singleton;

import java.io.IOException;
import java.util.Map;
import java.util.Observable;
import java.util.Observer;
import java.util.logging.Logger;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;

/**
 * An implementation of the authorization map manager.
 */
@ThreadSafe
@Singleton
public class AuthorizationMapManagerImpl implements AuthorizationMapManager {
  private static final Logger logger =
      Logger.getLogger(AuthorizationMapManagerImpl.class.getName());

  private final AuthorizationMethodFactory methodFactory;
  @GuardedBy("this") private ImmutableMap<AuthzMechanism, AuthzModule> modules;
  @GuardedBy("this") private AuthorizationMap authorizationMap;
  @GuardedBy("this") private AuthorizationMap fastAuthorizationMap;

  @Inject
  private AuthorizationMapManagerImpl(AuthorizationMethodFactory methodFactory) {
    super();
    this.methodFactory = methodFactory;
    modules = ImmutableMap.of();
    authorizationMap = null;
    fastAuthorizationMap = null;
    ConfigSingleton.addObserver(
        new Observer() {
          @Override
          public void update(Observable observable, Object object) {
            if (authorizationMap != null) {
              try {
                setFlexAuthorizer();
              } catch (IOException e) {
                throw new RuntimeException(e);
              }
            }
          }
        });
  }

  public synchronized void setModules(Map<AuthzMechanism, AuthzModule> modules) {
    this.modules = ImmutableMap.copyOf(modules);
  }

  @Override
  public synchronized AuthorizationMap getAuthorizationMap(boolean useFastAuthz)
      throws IOException {
    if (authorizationMap == null) {
      setFlexAuthorizer();
      Preconditions.checkNotNull(authorizationMap);
    }
    return useFastAuthz ? fastAuthorizationMap : authorizationMap;
  }

  private synchronized void setFlexAuthorizer()
      throws IOException {
    logger.info("Updating FlexAuthorizer from config:");
    FlexAuthorizer authorizer = ConfigSingleton.getConfig().getFlexAuthorizer();
    AuthorizationMap.Builder allBuilder = AuthorizationMap.builder();
    AuthorizationMap.Builder fastBuilder = AuthorizationMap.builder();
    for (FlexAuthzRoutingTableEntry entry : authorizer.getAllRoutingTable()) {
      FlexAuthzRule rule = entry.getAuthzRule();
      AuthzMechanism mech = rule.getAuthzMechType();
      if (mech == AuthzMechanism.FILE_SYSTEM) {
        // AuthzMechanism.FILE_SYSTEM is not supported anymore.
        // If a configuration file contains it then we ignore the rule.
        logger.warning("Rule for the file system is ignored. Url: " + entry.getUrlPattern());
        continue;
      }
      AuthzModule module = modules.get(mech);
      Preconditions.checkState(module != null, "Unknown authz mech: %s", mech);
      String pattern = entry.getUrlPattern();
      AuthorizationMethod method = methodFactory.create(module, rule);
      allBuilder.addRule(pattern, method);
      if (isFastMechanism(mech)) {
        fastBuilder.addRule(pattern, method);
      }
      logger.info("Rule: " + Stringify.object(pattern) + " --> " + mech);
    }
    this.authorizationMap = allBuilder.build();
    this.fastAuthorizationMap = fastBuilder.build();
  }

  private boolean isFastMechanism(AuthzMechanism mech) {
    return AuthzMechanism.CACHE.equals(mech)
        || AuthzMechanism.PER_URL_ACL.equals(mech)
        || AuthzMechanism.POLICY.equals(mech);
  }
}
