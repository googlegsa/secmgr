// Copyright 2008 Google Inc.
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

package com.google.enterprise.secmgr.common;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Preconditions;
import com.google.common.io.Files;
import java.io.File;
import java.io.IOException;

/**
 * Utilities for finding files.
 */
public class FileUtil {

  private static String contextDirectory;
  private static String commonDirectory;

  private static final String TESTDATA_ROOT = FileUtil.class.getResource("/").getPath();

  private static final String GOOGLE3_TEST_UTIL_CLASS = "com.google.testing.util.TestUtil";
  private static final String GET_SRC_DIR_METHOD = "getSrcDir";
  private static final String GET_TMP_DIR_METHOD = "getTmpDir";
  private static final String GOOGLE3_TESTDATA_ROOT =
      "/google3/javatests/com/google/enterprise/secmgr/testdata";
  private static final String NON_GOOGLE3_TESTDATA_ROOT = "testdata/mocktestdata/";

  private static final String BEGIN_PEM_CERTIFICATE_MARKER = "-----BEGIN CERTIFICATE-----";
  private static final String END_PEM_CERTIFICATE_MARKER = "-----END CERTIFICATE-----";

  private static final String BEGIN_PEM_KEY_MARKER = "-----BEGIN RSA PRIVATE KEY-----";
  private static final String END_PEM_KEY_MARKER = "-----END RSA PRIVATE KEY-----";

  // don't instantiate
  private FileUtil() {
  }

  /**
   * Initialize the context and common directories for testing.
   */
  public static void initializeTestDirectories() {
    contextDirectory = TESTDATA_ROOT;
    commonDirectory = TESTDATA_ROOT;
  }

  /**
   * Get the context directory.  This directory holds the config files used by
   * the security manager.
   *
   * @return The context directory as a string.
   */
  public static String getContextDirectory() {
    return contextDirectory;
  }

  /**
   * Get the common directory.  This directory holds all persistent state maintained by
   * the connector manager.
   *
   * @return The common directory as a string.
   */
  public static String getCommonDirectory() {
    // Allow override via command-line flags so that large tests can easily
    // specify a tmp directory.
    String testTmpDir = System.getProperty("google3.tmpdir");
    if (testTmpDir != null) {
      return testTmpDir;
    }
    return commonDirectory;
  }

  /**
   * Set the Context/Common directory.  To be called only from the servlet
   * initialization in a production environment.
   */
  public static void setContextDirectory(String directory) {
    contextDirectory = directory;
    commonDirectory = directory;
  }

  /**
   * Resolve relative filenames in the directory of the config files.
   *
   * @param filename A (potentially relative) filename.
   * @return An absolute File object.
   */
  public static File getContextFile(String filename) {
    Preconditions.checkNotNull(filename);
    return getContextFile(new File(filename));
  }

  /**
   * Resolve relative filenames in the directory of the config files.
   *
   * @param file A (potentially relative) File object.
   * @return An absolute File object.
   */
  public static File getContextFile(File file) {
    Preconditions.checkNotNull(file);
    return (file.isAbsolute()) ? file : new File(getContextDirectory(), file.toString());
  }

  /**
   * Resolve relative filenames in the common directory.
   *
   * @param filename A (potentially relative) filename.
   * @return An absolute File object.
   * @see #getCommonDirectory
   */
  public static File getCommonFile(String filename) {
    Preconditions.checkNotNull(filename);
    return getCommonFile(new File(filename));
  }

  /**
   * Resolve relative filenames in the common directory.
   *
   * @param file A (potentially relative) File object.
   * @return An absolute File object.
   * @see #getCommonDirectory
   */
  public static File getCommonFile(File file) {
    Preconditions.checkNotNull(file);
    return (file.isAbsolute()) ? file : new File(getCommonDirectory(), file.toString());
  }

  /**
   * Read a PEM-encoded certificate file and return the (usually Base64 encoded) inner content as
   * a string.
   *
   * @param file The file to read.
   * @return The (text-encoded) certificate.
   * @throws IOException if unable to read or parse the file.
   */
  public static String readPEMCertificateFile(File file)
      throws IOException {
    String certFile = Files.asCharSource(file, UTF_8).read();
    int start = certFile.indexOf(BEGIN_PEM_CERTIFICATE_MARKER);
    if (start < 0) {
      throw new IOException("Certificate file missing begin marker");
    }
    start += BEGIN_PEM_CERTIFICATE_MARKER.length();
    int end = certFile.indexOf(END_PEM_CERTIFICATE_MARKER, start);
    if (end < 0) {
      throw new IOException("Certificate file missing end marker");
    }
    return certFile.substring(start, end);
  }

  /**
   * Reads a PEM-encoded private key file and return the (usually Base64 encoded) inner content as 
   * a string.
   *
   * @param file The file to read.
   * @return The (text-encoded) private key
   * @throws IOException if unable to read or parse the file.
   */
  public static String readPEMPrivateKeyFile(File file)
      throws IOException {
    String certFile = Files.asCharSource(file, UTF_8).read();
    int start = certFile.indexOf(BEGIN_PEM_KEY_MARKER);
    if (start < 0) {
      throw new IOException("Key file missing begin marker");
    }
    start += BEGIN_PEM_KEY_MARKER.length();
    int end = certFile.indexOf(END_PEM_KEY_MARKER, start);
    if (end < 0) {
      throw new IOException("Key file missing end marker");
    }
    return certFile.substring(start, end);
  }
}
