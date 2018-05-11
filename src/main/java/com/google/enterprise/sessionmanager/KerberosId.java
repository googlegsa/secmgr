// Copyright 2018 Google Inc.
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

package com.google.enterprise.sessionmanager;

/** User with realm paired with expiration. */
public final class KerberosId {
  private final String user;
  private final Long expSecs;

  public KerberosId(String userWithRealm, Long expirationInSecs) {
    this.user = userWithRealm;
    this.expSecs = expirationInSecs;
  }

  public String getIdentity() {
    return user;
  }

  public Long getExpirationInSecs() {
    return expSecs;
  }
}
