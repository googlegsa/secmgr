// Copyright 2014 Google Inc.
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

import com.google.enterprise.secmgr.common.Resource;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.saml.SecmgrCredential;

import java.util.Collection;

/** Authorization method that does Authz based on {@code SecmgrCredential} */
public interface AuthorizeWithCredential {
  public AuthzResult authorize(Collection<Resource> resources, SecmgrCredential cred);
}
