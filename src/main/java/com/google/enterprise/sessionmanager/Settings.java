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

import java.io.File;

/**
 * This object contains the internal settings used by the SessionManager
 * for storage and maintenance of the back-end data.
 *
 * Settings are controlled by:
 * - platform customization (e.g. whether to use Chubby as the back-end storage
 *   (clusters), or whether to use files as the back-end (oneway/mini)
 * - admin console settings (e.g. length of a session timeout)
 *
 * TODO - this initial implementation is a place-holder.
 * In the final version,
 * settings will be read from a settings file maintained by a combination of
 * system customization scripts and the admin console.  If parsing that file
 * is expensive, this class will abstract the automatic caching of the parsing.
 *
 */
class Settings {

  // Internal data storage (protected to facilitate overrides by testing)
  protected String prefix;
  protected int timeoutSecs;

  private static final String PREFIX1 = "/mnt/rtcache/";
  private static final String PREFIX2 = "/tmp/";
  static final String BASEDIR = "session_manager/";

  // Temporary constructor - set the settings here for now
  Settings () {
    /* prefix directory: session data contains user passwords etc, so from a
     * security perspective, it's important to us that sessions be wiped out
     * upon machine-down.  Therefore, we really want session data to be stored
     * in a ramdisk.  On GSA's in the 5.0 time-frame, the best available ramdisk
     * is a tempfs system on /mnt/rtcache.  However, this directory doesn't
     * exists on non-GSA's (e.g. developer boxes, the unit testing framework,
     * etc).  So- we check if /mnt/rtcache exists, and if so, we place the
     * session manager store under there.  Otherwise, we fall back to /tmp
     */
    String prefixToUse = PREFIX1;
    File fileTest = new File(prefixToUse);
    try {
      if (!fileTest.exists()) {
        prefixToUse = PREFIX2;
      }
    } catch (SecurityException e) {
      prefixToUse = PREFIX2;
    }

    prefix = prefixToUse + BASEDIR;

    timeoutSecs = 30 * 60;                    // 30 minutes
  }


  /**
   * retrieve the filename prefix used for this sessionmanager.
   * Something like /ls/sessionmanager/ or /tmp/sessionmanager/.
   *
   * @return    the filename prefix; with a trailing slash
   */
  public String getPrefix() {
    return prefix;
  }
  
  /**
   * retrieve the amount of time to wait after the last access (read or write)
   * to a session before it is eligible for garbage collection
   *
   * @return    number of seconds since last access when a session is expired
   */
  public int getSessionTimeout() {
    return timeoutSecs;
  }

}
