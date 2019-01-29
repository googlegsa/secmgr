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

package com.google.enterprise.secmgr.identity;

import com.google.enterprise.secmgr.config.CredentialTypeName;
import java.io.Serializable;

/**
 * A credential.  Examples of credentials include: username, password, kerberos
 * ticket, X.509 certificate.
 */
public interface Credential extends Serializable {

  /**
   * Is it OK for this credential to be shared with others?
   *
   * Examples of public credentials include: username, X.509 credential.
   * Examples of private credentials include: password, private key.
   *
   * @return True if the credential is public, false if it's private.
   */
  public boolean isPublic();

  /**
   * @return The name of this credential's type.
   */
  public CredentialTypeName getTypeName();

  /**
   * @return True if the credential is verifiable.
   */
  public boolean isVerifiable();
}
