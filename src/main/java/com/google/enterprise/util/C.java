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

package com.google.enterprise.util;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 *  Security manager shared constants
 **/
public class C {

  /** The root string of GSA's SAML entity id. */
  public static final String GSA_ENTITY_ID_ROOT = "http://google.com/enterprise/gsa/";

  /**
   * The suffix string for GSA entity id.
   * A suffix is needed for the GSA because the security manager will claim the
   * entity id endpoint that's configured by the admin. The entityid+suffix is the
   * hidden entity id used by GSA to communicate with the secmgr.
   */
  public static final String GSA_ENTITY_ID_SUFFIX = "/gsa-actual";


  /**
   * Determines the appropriate entity ID to use from a given configured
   * entity param and the GSA's appliance id.
   *
   * If the entityId param is actually configured (nonnull, nonempty), this
   * function will simply return that value.  Otherwise, if it is
   * empty/unconfigured, we return a default value which combines a hardcoded
   * string with the appliance's id.
   */
  public static String getConfiguredEntityId(@Nullable String entityId,
      @Nonnull String applianceId) {
    if (entityId != null && !entityId.isEmpty()) {
      // if gsaEntityId is configured, just use it
      return entityId;
    } else {
      // else, build the default string using entConfigName
      return GSA_ENTITY_ID_ROOT + applianceId;
    }
  }


  /**
   * This accessor codifies the entity ID that the GSA uses for the GSA (nonsecmgr) services.
   */
  public static String entityIdForGsa(@Nonnull String configuredEntityId) {
    return configuredEntityId + GSA_ENTITY_ID_SUFFIX;
  }


  /**
   * This accessor codifies the entity ID that the GSA uses for the Security Manager.
   */
  public static String entityIdForSecMgr(@Nonnull String configuredEntityId) {
    return configuredEntityId;
  }
}
