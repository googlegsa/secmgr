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

package com.google.enterprise.sessionmanager;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * This class provides a basic implementation of the BackendInterface where
 * sessions are implemented as folders within a given prefix directory
 * (assumed, but not required, to be within /tmp/), and keys are implemented
 * as files within their session folders, containing the key's contents.
 * A time-stamp file is stored in the session's folder;  it's last-update time
 * will be maintained as the last time any key within a session was read or
 * written.
 *
 */
class BackendFilesBase implements BackendInterfaceBase {

  // -------------------------------------------------
  // INTERNAL STATE

  Settings settings;
  String overridePrefixDir;
  boolean serveLoggingEnabled = false;
  
  private static final Logger logger =
    Logger.getLogger(BackendFilesBase.class.getName());


  // -------------------------------------------------
  // Internal helpers

  /**
   * if in testing mode, return the TEST_TMPDIR as the base, rather than 
   * whatever is actually in the settings object.  This assures that multiple
   * uid's running tests won't interfere with each other, and allows the
   * testing infrastrcture to auto-cleanup after the test.
   */
  protected String getPrefix() {
    return (overridePrefixDir != null) ? overridePrefixDir : settings.getPrefix(); 
  }
  
  /**
   * translate a sessionId into the folder name for that session
   */
  protected String sessionDirName(String sessionId) {
    return getPrefix() + sessionId;
  }

  /**
   * return the filename for a key in a particualr session
   *
   * @param sessionId
   * @param key
   * @return            the filename for this key within this session
   */
  protected String keyFileName(String sessionId, String key) {
    return sessionDirName(sessionId) + "/sess_" + key + ".session";
  }

  /**
   * update the last-accessed time for the given session
   * (fails silently if the session does not exist)
   * @param sessionId
   */
  protected void touch(String sessionId) {
    File timefile = new File(sessionDirName(sessionId) + "/timer");
    boolean isNew;
    try {
      isNew = timefile.createNewFile();
    } catch (IOException e) {
      isNew = true;
    }

    if (!isNew) {
      timefile.setLastModified(System.currentTimeMillis());
    }
  }


  // -------------------------------------------------
  // Constructor

  BackendFilesBase (Settings settings) {
    this.settings = settings;

    String tmpDir = System.getProperty("TEST_TMPDIR");
    if (tmpDir == null) {
      tmpDir = System.getenv("TEST_TMPDIR");
    }

    if ((tmpDir != null) && (tmpDir.length() > 0)) {
      this.overridePrefixDir = tmpDir + "/" + settings.BASEDIR;
    } else {
      this.overridePrefixDir = null;
    }
  }


  // -------------------------------------------------
  // Public interface methods


  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#sessionExists
   */
  public boolean sessionExists(String sessionId) {
    File dir = new File(sessionDirName(sessionId));
    return dir.exists();
  }


  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#keyExists
   */
  public boolean keyExists(String sessionId, String key) {
    File file = new File(keyFileName(sessionId, key));
    return file.exists();
  }

  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#sessionAge
   */
  public long sessionAge(String sessionId)
      throws IndexOutOfBoundsException {
    File timefile = new File(sessionDirName(sessionId) + "/timer");
    if (!timefile.exists()) {
      String message = "tried to find age of non-existent session " + sessionId;
      logger.warning(message);
      throw new IndexOutOfBoundsException(message);
    }

    long deltaMils = System.currentTimeMillis() - timefile.lastModified();
    return deltaMils / 1000;
  }

  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#createSession
   */
  public void createSession(String sessionId) {
    File newdir = new File(sessionDirName(sessionId));
    boolean ok = newdir.mkdirs();
    if (!ok) {
      String message = "unable to create session " + sessionId
        + " (target=" + newdir.getAbsolutePath() + ")";
      logger.warning(message);
      throw new RuntimeException(message);
    }
    touch(sessionId);
  }

  /** @see com.google.enterprise.sessionmanager.BackendInterface#deleteSession */
  @Override
  public void deleteSession(String sessionId) throws IndexOutOfBoundsException {
    File dir = new File(sessionDirName(sessionId));
    if (!dir.exists()) {
      throw new IndexOutOfBoundsException("no such session");
    }

    File[] files = dir.listFiles();
    for (File file : files) {
      boolean ok = file.delete();
      if (!ok) {
        String message = "unable to delete key " + file.getName();
        logger.warning(message);
        throw new RuntimeException(message);
      }
    }
    boolean ok = dir.delete();
    if (!ok) {
      String message = "unable to delete session dir " + dir.getName();
      logger.warning(message);
      throw new RuntimeException(message);
    }
  }

  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#readKey
   */
  public byte[] readKey(String sessionId, String key)
      throws IndexOutOfBoundsException {
    File file = new File(keyFileName(sessionId, key));
    long size = file.length();
    byte[] buffer = new byte[(int) size];
    try {
      DataInputStream data = new DataInputStream(new FileInputStream(file));
      try {
        data.read(buffer);
      } catch (IOException e) {
        throw e;
      } finally {
        data.close();
      }
    } catch (java.io.FileNotFoundException e) {

      // we need to determine whether the session exists or not.
      // if so, this error just means the key isn't set yet, so return null.
      // if the entire session doesn't exist, we throw an exception
      // we'll determine this by trying to grab the session age

      try {
        sessionAge(sessionId);
      } catch (IndexOutOfBoundsException unused) {
        // if sessionAge fails, the whole session doesn't exist, so pass the
        // exception up to our caller
        String message = "Attempt to read key " + key
                + " from non existent session " + sessionId;
        logger.warning(message);
        throw new IndexOutOfBoundsException(message);
      }

      // if sessionAge worked, it's only the key that's missing
      return null;
    } catch (java.io.IOException e) {
      String message = "Unable to read session key file " + key
        + " for session " + sessionId;
      logger.warning(message);
      throw new IndexOutOfBoundsException(message);
    }
    touch(sessionId);
    return buffer;
  }

  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#writeData
   */
  public void writeData(String sessionId, String key, String contents)
      throws IndexOutOfBoundsException {
    // temporary hack
    File newdir = new File(sessionDirName(sessionId));
    newdir.mkdirs();
    writeData(sessionId, key, Utils.toBytesUtf8(contents));
  }

  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#writeCompressedData
   */
  public void writeCompressedData(String sessionId, String key, byte[] contents)
      throws IndexOutOfBoundsException {
   File file = new File(keyFileName(sessionId, key));
    try {
      DataOutputStream data = new DataOutputStream(new FileOutputStream(file));
      try {
        data.write(contents);
      } catch (IOException e) {
        throw new IOException();
      } finally {
        data.close();
      }
    } catch (java.io.FileNotFoundException e) {
      String message = "Unable to create session key file " + key
          + " for session " + sessionId;
      logger.warning(message);
      throw new IndexOutOfBoundsException(message);
    } catch (java.io.IOException e) {
      String message =
          "error writing to key file " + key + " for session " + sessionId;
      logger.warning(message);
      throw new IndexOutOfBoundsException(message);
    }
    touch(sessionId);
  }

  public void writeData(String sessionId, String key, byte[] value)
      throws IndexOutOfBoundsException {
    File file = new File(keyFileName(sessionId, key));
    try {
      DataOutputStream data = new DataOutputStream(new FileOutputStream(file));
      try {
        data.write(value);
      } catch (IOException e) {
        throw new IOException();
      } finally {
        data.close();
      }
    } catch (java.io.FileNotFoundException e) {
      String message = "Unable to create session key file " + key +
          " for session " + sessionId;
      logger.warning(message);
      throw new IndexOutOfBoundsException(message);
    } catch (java.io.IOException e) {
      String message = "error writing to key file " + key +
          " for session " + sessionId;
      logger.warning(message);
      throw new IndexOutOfBoundsException(message);
    }
    touch(sessionId);
  }

  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#listSessions
   */
  public List<String> listSessions() {
    List<String> output = new ArrayList<String>();
    File dir = new File(getPrefix());
    if (!dir.exists()) { return output; }

    File[] sessions = dir.listFiles();
    if (sessions != null) {
      for (File session : sessions) {
        if (session.isDirectory()) {
          output.add(session.getName());
        }
      }
    }
    return output;
  }

  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#listKeys
   */
    public List<String> listKeys(String sessionId) {
    List<String> output = new ArrayList<String>();
    File dir = new File(sessionDirName(sessionId));
    File[] sessions = dir.listFiles();
    for (File session : sessions) {
      if (session.isDirectory()) {
        output.add(session.getName());
        }
    }
    return output;
  }

  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#storeKrb5Identity
   */
  public KerberosId storeKrb5Identity(String sessionId, String spnegoBlob) {
    throw new RuntimeException("Method not implemented yet");
  }

  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#getKrb5TokenForServer
   */
  public KeyMaterial getKrb5TokenForServer(String sessionId, String server) {
    throw new RuntimeException("Method not implemented yet");
  }

  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#krb5CredentialsAreInitialized
   */
  public String getKrb5Identity(String sessionId) {
    throw new RuntimeException("Method not implemented yet");
  }

  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#getKrb5Ccache
   */
  public String getKrb5CcacheFilename(String sessionId) throws IndexOutOfBoundsException {
    throw new RuntimeException("Method not implemented yet");
  }

  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#parseKrb5Keytab
   */
  public String parseKrb5Keytab(String filepath) {
    throw new RuntimeException("Method not implemented yet");
  }
  
  /**
   * @see com.google.enterprise.sessionmanager.BackendInterface#getKrb5ServerNameIfEnabled
   */
  public String getKrb5ServerNameIfEnabled() {
    return null;  // Kerberos not enabled for this back end.
  }
}
