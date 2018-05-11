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

package com.google.enterprise.secmgr.http;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Ticker;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.inject.Singleton;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.Observable;
import java.util.Observer;

import javax.annotation.Nonnegative;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;
import javax.inject.Inject;

/**
 * This class keeps a table of per-host time-out records and uses that to
 * determine when a host should be considered unresponsive.  Each raw data point
 * is the number of timeouts for a host in a one-second sampling period.
 *
 * This raw data is then smoothed using an exponential moving average (see
 * http://en.wikipedia.org/wiki/Moving_average#Exponential_moving_average).
 * Once the smoothed value exceeds an upper threshold, the host is considered
 * unresponsive until the value drops below a corresponding lower threshold.
 *
 * While the host is unresponsive, no requests are made to that host.
 *
 */
@Singleton
@ThreadSafe
@ParametersAreNonnullByDefault
public final class SlowHostTracker {

  private final Ticker ticker;
  @GuardedBy("this") private TrackerInstance instance;

  private SlowHostTracker(Ticker ticker) {
    this.ticker = ticker;
    SecurityManagerConfig config;
    try {
      config = ConfigSingleton.getConfig();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    resetInstance(config);
    ConfigSingleton.addObserver(
        new Observer() {
          @Override
          public void update(Observable observable, Object arg) {
            resetInstance((SecurityManagerConfig) arg);
          }
        });
  }

  @Inject
  private SlowHostTracker() {
    this(Ticker.systemTicker());
  }

  @VisibleForTesting
  static SlowHostTracker getInstanceForTesting(Ticker ticker) {
    Preconditions.checkNotNull(ticker);
    return new SlowHostTracker(ticker);
  }

  private synchronized void resetInstance(SecurityManagerConfig config) {
    instance = new TrackerInstance(config);
  }

  private synchronized TrackerInstance getInstance() {
    return instance;
  }

  /**
   * An exception thrown by {@link #checkHost} when a host is unresponsive.
   */
  public static final class UnresponsiveHostException extends InterruptedIOException {
    private UnresponsiveHostException(String host) {
      super("No request to a slow host: " + host);
      bytesTransferred = 0;
    }
  }

  /**
   * Checks if a host is unresponsive.
   *
   * @param host A host name to check.
   * @throws UnresponsiveHostException if the host is unresponsive.
   */
  public void checkHost(String host)
      throws UnresponsiveHostException {
    if (isUnresponsive(host)) {
      throw new UnresponsiveHostException(host);
    }
  }

  /**
   * Checks if a host is unresponsive.
   *
   * @param host A host name to check.
   * @return True only if the host is unresponsive.
   */
  public boolean isUnresponsive(String host) {
    return getInstance().isUnresponsive(host);
  }

  /**
   * Records that a request to a given host timed out.
   *
   * @param host The host that the request was sent to.
   */
  public void recordHostTimeout(String host) {
    getInstance().recordHostTimeout(host);
  }

  @VisibleForTesting
  public void markAsUnresponsive(String host) {
    getInstance().markAsUnresponsive(host);
  }

  /**
   * An adapter that counts the number of timeouts if there's only a single
   * sample of date.
   */
  @VisibleForTesting
  long getNumberOfTimeouts(String host) {
    return getInstance().getNumberOfTimeouts(host);
  }

  /**
   * Erases all data from the tracker.
   */
  public void clearAllRecords() {
    getInstance().clearAllRecords();
  }

  /**
   * The tracker instance that does all the work.
   */
  @ThreadSafe
  private final class TrackerInstance {

    final double oneMinusAlpha;
    final double alpha;
    final double highThreshold;
    final double lowThreshold;
    final boolean enabled;
    // No synchronization needed -- the cache is thread-safe.
    final LoadingCache<String, HostEntry> hostTable;

    TrackerInstance(SecurityManagerConfig config) {

      int numberOfTimeouts = config.getSlowHostNumberOfTimeouts();
      int samplePeriod = config.getSlowHostSamplePeriod();
      int embargoPeriod = config.getSlowHostEmbargoPeriod();

      // These preconditions are already enforced by the admin console, so none of
      // them should throw an exception.  They are here because the arithmetic
      // depends on them.
      Preconditions.checkState(numberOfTimeouts > 0);
      Preconditions.checkState(samplePeriod > 0);
      Preconditions.checkState(embargoPeriod > 0);

      // An arbitrary ratio between the low and high thresholds.
      double thresholdRatio = 0.5d;

      // Alpha is chosen so that the time it takes to drop from highThreshold to
      // lowThreshold is embargoPeriod.
      oneMinusAlpha = Math.pow(thresholdRatio, 1d / embargoPeriod);
      alpha = 1d - oneMinusAlpha;

      // highThreshold is chosen so that it will be exceeded when we get an
      // appropriate number of timeouts over the sample period.  This is a
      // pretty close estimate, as show by the unit tests.
      double factors = 0d;
      double factor = 1d;
      for (int i = 0; i < samplePeriod; i += 1) {
        factors += factor;
        factor *= oneMinusAlpha;
      }
      highThreshold = alpha * factors * numberOfTimeouts / samplePeriod;

      // lowThreshold is related by the arbitrary ratio.
      lowThreshold = highThreshold * thresholdRatio;

      enabled = config.getSlowHostTrackerEnabled();
      hostTable = CacheBuilder.newBuilder()
          .maximumSize(config.getSlowHostTrackerSize())
          .build(
              new CacheLoader<String, HostEntry>() {
                @Override
                public HostEntry load(String host) {
                  return new HostEntry();
                }
              });
    }

    boolean isUnresponsive(String host) {
      HostEntry hostEntry = hostTable.getIfPresent(host);
      return (hostEntry != null) ? hostEntry.isUnresponsive() : false;
    }

    void recordHostTimeout(String host) {
      if (enabled) {
        hostTable.getUnchecked(host).incrementSample();
      }
    }

    void markAsUnresponsive(String host) {
      if (enabled) {
        hostTable.getUnchecked(host).markAsUnresponsive();
      }
    }

    long getNumberOfTimeouts(String host) {
      HostEntry hostEntry = hostTable.getIfPresent(host);
      return (hostEntry != null) ? Math.round(hostEntry.currentValue() / alpha) : 0;
    }

    void clearAllRecords() {
      hostTable.invalidateAll();
    }

    /**
     * A host-table entry.
     */
    @ThreadSafe
    final class HostEntry {
      // The accumulated value for t < currentSampleTime.
      @GuardedBy("this") double value;
      // The number of timeouts for t == currentSampleTime.
      @GuardedBy("this") int currentSample;
      @GuardedBy("this") @Nonnegative long currentSampleTime;
      // Whether or not the host is currently unresponsive.
      @GuardedBy("this") boolean unresponsive;

      HostEntry() {
        value = 0.0;
        currentSample = 0;
        currentSampleTime = getNow();
        unresponsive = false;
      }

      // Current time in seconds.
      long getNow() {
        return ticker.read() / 1000000000;
      }

      // For testing, forces host into unresponsive state.
      synchronized void markAsUnresponsive() {
        value = highThreshold;
        currentSample = 0;
        currentSampleTime = getNow();
        unresponsive = true;
      }

      synchronized boolean isUnresponsive() {
        double v = currentValue();
        if (unresponsive) {
          if (v < lowThreshold) {
            unresponsive = false;
          }
        } else {
          if (v > highThreshold) {
            unresponsive = true;
          }
        }
        return unresponsive;
      }

      synchronized double currentValue() {
        updateSample();
        return (alpha * currentSample) + (oneMinusAlpha * value);
      }

      synchronized void incrementSample() {
        updateSample();
        currentSample += 1;
      }

      void updateSample() {
        long now = getNow();
        if (now > currentSampleTime) {
          // Bump state forward by one sample.
          value = (alpha * currentSample) + (oneMinusAlpha * value);
          currentSample = 0;
          currentSampleTime += 1;
          // Bump state forward by intermediate empty samples.
          if (now > currentSampleTime) {
            value *= Math.pow(oneMinusAlpha, (now - currentSampleTime));
            currentSampleTime = now;
          }
        }
      }
    }
  }
}
