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

package com.google.enterprise.secmgr.authncontroller;

/**
 * The result code returned from the authentication controller to the servlet
 * that invoked it.
 */
public enum AuthnResult {
  // AuthN is finished, the frontend should generate a successful result.
  SUCCESSFUL,

  // AuthN is finished, the frontend should generate a failure result.
  UNSUCCESSFUL,

  // AuthN has not yet finished, the authentication controller has generated
  // something (such as a login form), and the frontend should continue the
  // AuthN sequence to allow the user to take action with it.
  UNFINISHED,
}
