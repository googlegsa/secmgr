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

import com.google.common.base.Function;
import com.google.common.collect.Iterables;
import com.google.enterprise.secmgr.authncontroller.AuthnController;
import com.google.enterprise.secmgr.common.FileUtil;
import com.google.enterprise.secmgr.config.ConfigParams;
import com.google.enterprise.secmgr.config.ConfigSingleton;
import com.google.enterprise.secmgr.config.CredentialGroup;
import com.google.enterprise.secmgr.config.SecurityManagerConfig;
import com.google.enterprise.secmgr.servlets.SecurityManagerServletConfig;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.logging.LogManager;
import junit.framework.AssertionFailedError;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestResult;
import junit.framework.TestSuite;
import junit.textui.TestRunner;
import org.easymock.EasyMockSupport;
import org.joda.time.DateTimeUtils;

/**
 * Testing framework for security manager.  Handles Guice initialization.
 */
public class SecurityManagerTestCase extends TearDownTestCase {

  public static final String GSA_TESTING_ISSUER = "http://google.com/enterprise/gsa/testing";

  static {
    try {
      FileUtil.initializeTestDirectories();
      File loggingPropertiesFile = FileUtil.getContextFile("logging.properties");
      InputStream loggingPropertiesStream = new FileInputStream(loggingPropertiesFile);
      try {
        LogManager.getLogManager().readConfiguration(loggingPropertiesStream);
      } finally {
        loggingPropertiesStream.close();
      }
    } catch (IOException e) {
      fail("Error initializing FileUtil: " + e.toString());
    }
    SecurityManagerServletConfig.initializeGson();
    SecurityManagerServletConfig.makeTestingInjector("AuthSites.json");
  }

  public SecurityManagerTestCase() {
    super();
  }

  public SecurityManagerTestCase(String name) {
    super();
    setName(name);
  }

  @Override
  protected void setUp() throws Exception {
    super.setUp();
    ConfigSingleton.reset();
    ConfigSingleton.getInstance(AuthnController.class).reset();

    // Make sure clock is set to normal value.
    DateTimeUtils.setCurrentMillisSystem();
    addTearDown(new TearDown() {
      @Override
      public void tearDown() throws Exception {
        // Make sure clock is set to normal value.
        DateTimeUtils.setCurrentMillisSystem();
      }
    });
    // EasyMock @Mock support
    EasyMockSupport.injectMocks(this);
  }

  protected static SecurityManagerConfig makeConfig(Iterable<CredentialGroup> credentialGroups) {
    SecurityManagerConfig config;
    try {
      config = ConfigSingleton.getConfigNoOverride();
    } catch (IOException e) {
      fail("Unable to read config file: " + e.getMessage());
      throw new IllegalStateException(e);
    }
    return SecurityManagerConfig.make(
        credentialGroups, config.getParams(), config.getFlexAuthorizer());
  }

  protected static void updateConfigParams(ConfigParamsUpdater updater) {
    SecurityManagerConfig config = getConfig();
    ConfigParams.Builder builder = ConfigParams.builder(config.getParams());
    updater.apply(builder);
    ConfigSingleton.setConfig(
        SecurityManagerConfig.make(
            config.getCredentialGroups(), builder.build(), config.getFlexAuthorizer()));
  }

  /**
   * An argument type for {@link #updateConfigParams}.
   */
  protected interface ConfigParamsUpdater {
    void apply(ConfigParams.Builder builder);
  }

  protected static SecurityManagerConfig getConfig() {
    try {
      return ConfigSingleton.getConfig();
    } catch (IOException e) {
      fail("Unable to read config file: " + e.getMessage());
      throw new IllegalStateException(e);
    }
  }

  // When jUnit is run from Eclipse, this file looks like it should contain
  // test cases, and an error results if it doesn't, so add a do-nothing test.
  public void testNothing() { }

  public static void runTest(RunnableTest test) {
    runTestCase(runnableTestToTestCase(test));
  }

  public static void runTests(Iterable<? extends RunnableTest> tests) {
    runTestCases(Iterables.transform(tests, RUNNABLE_TEST_CONVERTER));
  }

  private static final Function<RunnableTest, Test> RUNNABLE_TEST_CONVERTER =
      new Function<RunnableTest, Test>() {
        @Override
        public Test apply(RunnableTest test) {
          return runnableTestToTestCase(test);
        }
      };

  private static TestCase runnableTestToTestCase(final RunnableTest test) {
    return new TestCase() {
      @Override
      public void runTest() {
        String result = test.runTest();
        if (result != null) {
          fail(result);
        }
      }
    };
  }

  /**
   * Runs a manually-constructed test.
   *
   * @param test The test to be run.
   * @throws AssertionFailedError if the test had one or more failures.
   */
  public static void runTestCase(Test test) {
    TestRunner runner = (new TestRunner(getPrintStream()));
    TestResult result = runner.doRun(test);
    if (!result.wasSuccessful()) {
      throw new AssertionFailedError("Nested test had failures.");
    }
  }

  private static PrintStream getPrintStream() {
    try {
      return new PrintStream(System.err, true, "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Runs multiple manually-constructed tests.  All of the tests are run
   * independently, so the failure of one doesn't prevent the others from
   * running.
   *
   * @param tests The tests to be run.
   * @throws AssertionFailedError if any of the tests had one or more failures.
   */
  public static void runTestCases(Test... tests) {
    TestSuite suite = new TestSuite();
    for (Test test : tests) {
      flattenTest(test, suite);
    }
    runTestCase(suite);
  }

  /**
   * Runs multiple manually-constructed tests.  All of the tests are run
   * independently, so the failure of one doesn't prevent the others from
   * running.
   *
   * @param tests The tests to be run.
   * @throws AssertionFailedError if any of the tests had one or more failures.
   */
  public static void runTestCases(Iterable<Test> tests) {
    TestSuite suite = new TestSuite();
    for (Test test : tests) {
      flattenTest(test, suite);
    }
    runTestCase(suite);
  }

  private static void flattenTest(Test test, TestSuite suite) {
    if (test instanceof TestSuite) {
      Enumeration<?> tests = ((TestSuite) test).tests();
      while (tests.hasMoreElements()) {
        flattenTest(Test.class.cast(tests.nextElement()), suite);
      }
    } else {
      suite.addTest(test);
    }
  }
}
