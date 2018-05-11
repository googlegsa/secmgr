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
package com.google.enterprise.logmanager;

/**
 * Flag defaults values for LogClient.java
 * We're using this class as intermediary between logmanager and secmgr.
 */
public class LogClientParameters {

  public static boolean enableLogManager = false;
  public static boolean recordUsernames = true;
  public static final String LOG_MANAGER_SERVER = "localhost:7331";

  // Magic RequestID that can be used to disable logging; mostly for use by
  // any legacy interfaces that require a requestid but don't actually use
  // or know how to use it.
  public static final String DO_NOT_LOG = "DO_NOT_LOG_REQUEST_ID";
  public static final String LINE_SEPARATOR = "\n";
  public static final String ID_NOT_LOGGED = "ID_NOT_LOGGED";


  private LogClientParameters() {
  }


}
