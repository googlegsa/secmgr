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

package com.google.enterprise.secmgr.mock;

import com.google.enterprise.secmgr.authncontroller.SessionSnapshot;
import com.google.enterprise.secmgr.authzcontroller.AuthorizationMethod;
import com.google.enterprise.secmgr.common.AuthzStatus;
import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.modules.AuthzResult;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * A mock authorization method.
 */
public class MockAuthorizationMethod implements AuthorizationMethod {

  private final String key;
  private final String methodName;

  private MockAuthorizationMethod(String key) {
    this.key = key;
    StringBuilder builder = new StringBuilder();
    builder.append("{key:'");
    builder.append(key);
    builder.append("', class:'");
    builder.append(this.getClass().getSimpleName());
    builder.append("'}");
    this.methodName = builder.toString();
  }

  @Override
  public String getName() {
    return key;
  }

  @Override
  public int getTimeout() {
    return 0;
  }

  @Override
  public String toString() {
    return methodName;
  }

  @Override
  public AuthzResult authorize(Collection<Resource> resources, SessionSnapshot snapshot) {
    AuthzResult.Builder builder = AuthzResult.builder();
    for (Resource resource : resources) {
      builder.put(resource.getUrl(),
          resource.getUrl().contains(key)
          ? AuthzStatus.PERMIT
          : AuthzStatus.INDETERMINATE);
    }
    return builder.build();
  }

  public String getKey() {
    return key;
  }

  private static Map<String, MockAuthorizationMethod> instanceList =
      new HashMap<String, MockAuthorizationMethod>();

  public static MockAuthorizationMethod forName(String key) {
    MockAuthorizationMethod m = instanceList.get(key);
    if (m != null) {
      return m;
    }
    m = new MockAuthorizationMethod(key);
    instanceList.put(key, m);
    return m;
  }
}
