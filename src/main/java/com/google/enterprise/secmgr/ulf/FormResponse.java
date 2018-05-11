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

package com.google.enterprise.secmgr.ulf;

import javax.annotation.concurrent.Immutable;

/**
 * The response to an individual ULF entry.
 */
@Immutable
public class FormResponse {

  private final FormElement element;
  private final String username;
  private final String password;

  public FormResponse(FormElement element, String username, String password) {
    this.element = element;
    this.username = username;
    this.password = password;
  }

  public FormElement getElement() {
    return element;
  }

  public String getUsername() {
    return username;
  }

  public String getPassword() {
    return password;
  }
}
