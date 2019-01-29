// Copyright 2008 Google Inc.
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

import java.io.Serializable;
import javax.annotation.concurrent.Immutable;

/**
 * A FormElement represents a single form component in the Universal Login form.
 * This data structure serves as the storage for the backend state of the
 * Universal Login form UI.
 */
@Immutable
public class FormElement implements Serializable {

  private final String name;
  private final String displayName;
  private final String username;
  private final boolean active;
  private final boolean enabled;

  public FormElement(String name, String displayName, boolean active, boolean enabled,
      String username) {
    this.name = name;
    this.displayName = displayName;
    this.username = username;
    this.active = active;
    this.enabled = enabled;
  }

  public String getName() {
    return name;
  }

  public String getDisplayName() {
    return displayName;
  }

  public String getUsername() {
    return username;
  }

  public boolean isActive() {
    return active;
  }

  public boolean isEnabled() {
    return enabled;
  }
}
