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

package com.google.enterprise.secmgr.mock;

import java.io.IOException;

import javax.servlet.ServletException;

/**
 * An interface implemented by mock back-end servers.  This interface simplifies
 * a server's use with {@link MockIntegration}.
 */
public interface MockServer {
  /**
   * Adds this server to the given integration.
   *
   * @param integration The integration to add this server to.
   */
  public void addToIntegration(MockIntegration integration)
      throws IOException, ServletException;

  /**
   * @return The context URL string for this server.
   */
  public String getContextUrl();

  /**
   * @return The sample URL string for this server.
   */
  public String getSampleUrl();

  /**
   * Resets any local state in the server.
   */
  public void reset();
}
