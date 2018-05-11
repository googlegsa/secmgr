// Copyright 2011 Google Inc.
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

package com.google.enterprise.secmgr.docfetchercontroller;

import com.google.enterprise.secmgr.authncontroller.SessionView;
import com.google.enterprise.secmgr.common.StringPair;
import com.google.enterprise.secmgr.http.PageFetcherResult;

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;

/**
 * The top-level document fetcher interface.
 */
@ParametersAreNonnullByDefault
public interface DocumentFetcherController {
  /**
   * Fetch a resource using credentials stored in the session.
   * @param resource The address of the resource to download.
   * @param view The session view to use during the fetch.
   * @throws IOException Thrown if an error occurs during the fetch.
   * @return The requested resource (body included).
   */
  @Nonnull
  public PageFetcherResult fetch(String resource,
      Iterable<StringPair> headers,
      SessionView view) throws IOException;
}
