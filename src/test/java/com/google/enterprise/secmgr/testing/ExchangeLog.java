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

package com.google.enterprise.secmgr.testing;

import static javax.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static javax.servlet.http.HttpServletResponse.SC_OK;
import static javax.servlet.http.HttpServletResponse.SC_FOUND;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import java.util.Iterator;
import java.util.List;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.servlet.http.HttpServletResponse;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * A simple framework for logging HTTP exchanges over the mock HTTP transport.
 * Provides support for comparing the logged exchanges with given expectations.
 */
public final class ExchangeLog {
  /**
   * The HTTP method in a log entry.
   */
  public enum Method {
    GET, POST
  }

  private Method method;
  private String servletName;
  private final ExchangeLog parent;
  private final List<ExchangeLog> children;
  private int status;

  private ExchangeLog(ExchangeLog parent) {
    this.parent = parent;
    children = Lists.newArrayList();
    if (parent != null) {
      parent.getChildren().add(this);
    }
  }

  public Method getMethod() {
    return method;
  }

  public void setMethod(Method method) {
    this.method = method;
  }

  public String getServletName() {
    return servletName;
  }

  public void setServletName(String servletName) {
    this.servletName = servletName;
  }

  private ExchangeLog getParent() {
    return parent;
  }

  public List<ExchangeLog> getChildren() {
    return children;
  }

  public int getStatus() {
    return status;
  }

  public void setStatus(int status) {
    this.status = status;
  }

  public void updateFromResponse(HttpServletResponse response) {
    MockHttpServletResponse r = (MockHttpServletResponse) response;
    setStatus(r.getStatus());
  }

  public void assertMatches(ExchangeLog actual) {
    if (this.getMethod() != actual.getMethod() ||
        !this.getServletName().equals(actual.getServletName())) {
      throw new IllegalStateException(
          "Expected: " + this.getMethod() + " on " + this.getServletName() +
          "; Actual: " + actual.getMethod() + " on " + actual.getServletName());
    }
    assertListsOfExchangeLogsMatch(this.getChildren(), actual.getChildren());
    if (this.getStatus() != actual.getStatus()) {
      throw new IllegalStateException(
          "At: " + this.getMethod() + " on " + this.getServletName() +
          "; Expected: status " + this.getStatus() +
          "; Actual: status " + actual.getStatus());
    }
  }

  public static void assertListsOfExchangeLogsMatch(List<ExchangeLog> expected,
      List<ExchangeLog> actual) {
    Iterator<ExchangeLog> ai = actual.iterator();
    for (ExchangeLog child : expected) {
      if (!ai.hasNext()) {
        throw new IllegalStateException(
            "Expected: " + child.getMethod() + " on " + child.getServletName() +
            "; Actual: no call");
      }
      ExchangeLog aChild = ai.next();
      child.assertMatches(aChild);
    }
    if (ai.hasNext()) {
      ExchangeLog aChild = ai.next();
      throw new IllegalStateException(
          "Expected: no call; Actual: " + aChild.getMethod() +
          " on " + aChild.getServletName());
    }
  }

  /**
   * A builder factory for exchange-log instances.
   */
  @ThreadSafe
  public static class Builder {
    @GuardedBy("this") private List<ExchangeLog> topLevel;
    @GuardedBy("this") private ThreadLocal<ExchangeLog> current;

    public Builder() {
      reset();
    }

    public synchronized void reset() {
      topLevel = Lists.newArrayList();
      current = new ThreadLocal<ExchangeLog>();
    }

    public synchronized ExchangeLog push() {
      ExchangeLog parent = current.get();
      ExchangeLog e = new ExchangeLog(parent);
      if (parent == null) {
        topLevel.add(e);
      }
      current.set(e);
      return e;
    }

    public synchronized void pop(ExchangeLog e) {
      current.set(e.getParent());
    }

    public synchronized List<ExchangeLog> getExchangeLogs() {
      return topLevel;
    }
  }

  public static String stringifyExchangeLogs(List<ExchangeLog> logs) {
    ImmutableList.Builder<LogItem> builder = ImmutableList.builder();
    for (ExchangeLog log : logs) {
      builder.add(log.convertToLogItem());
    }
    return stringifyLogItem(new LogSequence(builder.build().toArray(new LogItem[0])));
  }

  private LogItem convertToLogItem() {
    ImmutableList.Builder<LogItem> childrenBuilder = ImmutableList.builder();
    for (ExchangeLog child : getChildren()) {
      childrenBuilder.add(child.convertToLogItem());
    }
    List<LogItem> children = childrenBuilder.build();
    return logSequence(
        new LogRequest(getMethod(), getServletName(),
            new LogSequence(children.toArray(new LogItem[0]))),
        new LogResponse(getStatus()));
  }

  // **************** Support for incremental construction ****************

  // See SamlSsoTest for usage examples of this interface.

  public static LogItem logGet(String servletName, LogItem... children) {
    return new LogRequest(Method.GET, servletName, new LogSequence(children));
  }

  public static LogItem logPost(String servletName, LogItem... children) {
    return new LogRequest(Method.POST, servletName, new LogSequence(children));
  }

  public static LogItem logResponse(int status) {
    return new LogResponse(status);
  }

  public static LogItem logSequence(LogItem... items) {
    return new LogSequence(items);
  }

  public static LogItem logOk() {
    return logResponse(SC_OK);
  }

  public static LogItem logForbidden() {
    return logResponse(SC_FORBIDDEN);
  }

  public static LogItem logRedirect(String servletName,
      LogItem... children) {
    return logSequence(logResponse(SC_FOUND), logGet(servletName, children));
  }

  public static List<ExchangeLog> convertLogItem(LogItem item) {
    List<ExchangeLog> result = Lists.newArrayList();
    convertCompleteLogItem(item, result);
    return result;
  }

  private static void convertCompleteLogItem(LogItem item, List<ExchangeLog> result) {
    if (item.convert(null, result) != null) {
      throw new IllegalStateException("Log item doesn't end with a response.");
    }
  }

  public static String stringifyLogItem(LogItem item) {
    StringBuilder builder = new StringBuilder();
    item.stringify(builder, "");
    return builder.toString();
  }

  /**
   * A base class for log items.
   */
  public abstract static class LogItem {
    abstract ExchangeLog convert(ExchangeLog exchange, List<ExchangeLog> result);
    abstract void stringify(StringBuilder builder, String indent);
    @Override
    public String toString() {
      return stringifyLogItem(this);
    }
  }

  private static final String INCREMENTAL_INDENT = "    ";

  /**
   * A log item representing an HTTP request.
   */
  private static class LogRequest extends LogItem {
    private final Method method;
    private final String servletName;
    private final LogSequence children;

    public LogRequest(Method method, String servletName, LogSequence children) {
      this.method = method;
      this.servletName = servletName;
      this.children = children;
    }

    @Override
    ExchangeLog convert(ExchangeLog exchange, List<ExchangeLog> result) {
      if (exchange != null) {
        throw new IllegalStateException("Request in incorrect position.");
      }
      exchange = new ExchangeLog(null);
      exchange.setMethod(method);
      exchange.setServletName(servletName);
      convertCompleteLogItem(children, exchange.getChildren());
      return exchange;
    }

    @Override
    void stringify(StringBuilder builder, String indent) {
      builder.append(indent);
      builder.append("request: ");
      builder.append(method.toString());
      builder.append(" ");
      builder.append(servletName);
      builder.append("\n");
      children.stringify(builder, indent + INCREMENTAL_INDENT);
    }
  }

  private static class LogResponse extends LogItem {
    private final int status;

    public LogResponse(int status) {
      this.status = status;
    }

    @Override
    ExchangeLog convert(ExchangeLog exchange, List<ExchangeLog> result) {
      if (exchange == null) {
        throw new IllegalStateException("Response in incorrect position.");
      }
      exchange.setStatus(status);
      result.add(exchange);
      return null;
    }

    @Override
    void stringify(StringBuilder builder, String indent) {
      builder.append(indent);
      builder.append("response: ");
      builder.append(status);
      builder.append("\n");
    }
  }

  private static class LogSequence extends LogItem {
    private final LogItem[] items;

    public LogSequence(LogItem[] items) {
      this.items = items;
    }

    @Override
    ExchangeLog convert(ExchangeLog exchange, List<ExchangeLog> result) {
      for (LogItem item : items) {
        exchange = item.convert(exchange, result);
      }
      return exchange;
    }

    @Override
    void stringify(StringBuilder builder, String indent) {
      for (LogItem item : items) {
        item.stringify(builder, indent);
      }
    }
  }
}
