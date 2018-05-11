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

import java.util.List;
import javax.annotation.Nullable;

public class LogClient {

  public LogClient(String sourceLogger) {
  }

  public LogClient(String sourceLogger, String server) {
  }

  public void log(String requestId, String message) {
  }

  public void info(String requestId, String message) {
  }

  public void info(String requestId, List<String> multiLineMessage) {
  }

  public void debug(String requestId, String message) {
  }

  public void debug(String requestId, List<String> multiLineMessage) {
  }

  public void critical(String requestId, String message) {
  }

  public void critical(String requestId, List<String> multiLineMessage) {
  }

  public void logSessionId(String requestId, String sessionId) {
  }

  /**
   * Logs the username for this request.
   */
  public void logUsername(String requestId, String userId) {
  }

  /**
   * Logs the query term for this request.
   */
  public void logQuery(String requestId, String queryString) {
  }

  public BatchLogger getBatchLogger() {
    return new BatchLogger();
  }

  public final class BatchLogger {

    public void info(String requestId, String message) {
    }

    public void debug(String requestId, String message) {
    }

    public void critical(String requestId, String message) {
    }

    public void log(String requestId, String message) {
    }

    public void send() {
    }
  }
}
