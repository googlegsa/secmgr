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

package com.google.enterprise.secmgr.http;

import com.google.common.base.Ticker;
import com.google.enterprise.secmgr.config.ConfigParams;
import com.google.enterprise.secmgr.config.ParamName;
import com.google.enterprise.secmgr.http.SlowHostTracker.UnresponsiveHostException;
import com.google.enterprise.secmgr.mock.MockHttpClient;
import com.google.enterprise.secmgr.mock.MockHttpServer;
import com.google.enterprise.secmgr.mock.MockHttpTransport;
import com.google.enterprise.secmgr.mock.MockSlowServer;
import com.google.enterprise.secmgr.testing.SecurityManagerTestCase;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.URL;

import javax.servlet.ServletException;

/**
 * Tests for the {@link SlowHostTracker} class.
 *
 */
public class SlowHostTrackerTest extends SecurityManagerTestCase {

  private static final String GOOD_HOST = "goodHost";
  private static final String GOOD_URL = "http://goodHost/good";
  private static final String SLOW_HOST = "slowHost";
  private static final String SLOW_URL = "http://slowHost/slow";

  private final TestTicker ticker;
  private final SlowHostTracker tracker;
  private final HttpRequester requester;

  public SlowHostTrackerTest()
      throws ServletException {
    ticker = new TestTicker();
    tracker = SlowHostTracker.getInstanceForTesting(ticker);

    MockHttpTransport transport = new MockHttpTransport();
    transport.registerServlet(GOOD_URL, new MockHttpServer());
    transport.registerServlet(SLOW_URL, new MockSlowServer());
    HttpClientUtil.setHttpClient(new MockHttpClient(transport));
    requester = HttpRequester.builder()
        .setPageFetcher(PageFetcher.getInstanceForTesting(tracker))
        .build();
  }

  @Override
  public void setUp()
      throws Exception {
    super.setUp();
    ticker.reset();
    updateConfigParams(
        new ConfigParamsUpdater() {
          @Override
          public void apply(ConfigParams.Builder builder) {
            builder.put(ParamName.SLOW_HOST_TRACKER_ENABLED, true);
          }
        });
  }

  /**
   * A simple ticker that we can manipulate.
   */
  private static final class TestTicker extends Ticker {
    long value;

    void reset() {
      value = Ticker.systemTicker().read();
    }

    void advance(long n) {
      value += n * 1000000000;
    }

    @Override
    public long read() {
      return value;
    }
  }

  // Test that a normal fetch works without generating a time-out record.
  public void testFetchSuccess()
      throws IOException {
    assertEquals(0, tracker.getNumberOfTimeouts(GOOD_HOST));
    requester.runExchange(new URL(GOOD_URL), null);
    assertEquals(0, tracker.getNumberOfTimeouts(GOOD_HOST));
  }

  // Confirm that a time-out is properly recorded.
  public void testFetchTimeout() {
    assertEquals(0, tracker.getNumberOfTimeouts(SLOW_HOST));
    slowFetch(requester);
    assertEquals(1, tracker.getNumberOfTimeouts(SLOW_HOST));
  }

  // Confirm that the number of time-outs increases up to the limit but does not
  // exceed it.
  public void testFetchSlowHost() {
    tracker.markAsUnresponsive(SLOW_HOST);
    try {
      requester.runExchange(new URL(SLOW_URL), null);
      fail("Timeout exception should have been thrown");
    } catch (UnresponsiveHostException e) {
      // expected.
    } catch (IOException e) {
      e.printStackTrace();
      fail("I/O exception was thrown: " + e.getMessage());
    }
  }

  public void testNumberOfTimeouts() {
    tryNumberOfTimeouts(5);
    tryNumberOfTimeouts(10);
    tryNumberOfTimeouts(20);
    tryNumberOfTimeouts(50);
    tryNumberOfTimeouts(100);
    tryNumberOfTimeouts(200);
    tryNumberOfTimeouts(500);
    tryNumberOfTimeouts(1000);
    tryNumberOfTimeouts(2000);
    tryNumberOfTimeouts(5000);
  }

  private void tryNumberOfTimeouts(int numberOfTimeouts) {
    setNumberOfTimeouts(numberOfTimeouts);
    double increment = (double) numberOfTimeouts / (double) getConfig().getSlowHostSamplePeriod();
    double sum = 0;
    int n = 0;
    while (!tracker.isUnresponsive(SLOW_HOST)) {
      sum += increment;
      while (n <= (sum - 1)) {
        tracker.recordHostTimeout(SLOW_HOST);
        n += 1;
      }
      ticker.advance(1);
    }
    assertTrue("number of timeouts too small; limit: " + numberOfTimeouts + ", actual: " + n,
        n >= numberOfTimeouts);
    double upperLimit = numberOfTimeouts * 1.01d;
    assertTrue("number of timeouts too large; limit: " + upperLimit + ", actual: " + n,
        n <= upperLimit);
  }

  private void setNumberOfTimeouts(final int numberOfTimeouts) {
    updateConfigParams(
        new ConfigParamsUpdater() {
          @Override
          public void apply(ConfigParams.Builder builder) {
            builder.put(ParamName.SLOW_HOST_NUMBER_OF_TIMEOUTS, numberOfTimeouts);
          }
        });
  }

  public void testEmbargoPeriod() {
    tracker.markAsUnresponsive(SLOW_HOST);
    int i = 1;
    while (tracker.isUnresponsive(SLOW_HOST)) {
      ticker.advance(1);
      i += 1;
    }
    assertEquals(getConfig().getSlowHostEmbargoPeriod(), i);
  }

  // Do a fetch that times out.
  private static void slowFetch(HttpRequester requester) {
    try {
      requester.runExchange(new URL(SLOW_URL), null);
      fail("Timeout exception should have been thrown");
    } catch (InterruptedIOException e) {
      // expected.
    } catch (IOException e) {
      e.printStackTrace();
      fail("I/O exception was thrown: " + e.getMessage());
    }
  }
}
