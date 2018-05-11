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

import com.google.common.annotations.VisibleForTesting;
import java.util.Formatter;
import java.util.List;
import java.util.Random;
import java.util.logging.Logger;

/**
 * This class provides an implementation of the SessionManagerInterface.
 *
 * This class is actually a reasonably thin layer between the
 * SessionManagerInterface and a BackendInterface implementation.  This layer
 * contains settings to determine what type of Backend to instantiate,
 * session name creation, and basic garbage collection logic.
 */
public class SessionManagerBase implements SessionManagerInterfaceBase {

  // -------------------------------------------------
  // INTERNAL STATE (set up at constuction)

  /* these are protected to facilitate testing - test classes may wish to
   * extend and override these for better local operation
   */

  protected Settings settings;      // package wide settings

  private static final Logger logger =
      Logger.getLogger(SessionManagerBase.class.getName());

  // for secure session name creation
  private static final Random random = new Random();

  protected BackendInterfaceBase backend;

  // Temp var that will be filled with random bytes.
  // Declared static just to avoid GC overhead.
  private static final byte[] randomBytes = new byte[16];
  // Another tmp var that declare here so as to only
  // create once.
  private static final StringBuilder sidBuilder =
        new StringBuilder(randomBytes.length * 2);

  //-------------------------------------------------
  // INTERNAL HELPER ROUTINES

  /**
   * Generate a 128-bit (16 byte) cryptographically secure random session name.
   *
   * @return    random printable string small enough for a cookie but large
   *            enough to be unguessable and secure enough to be unpredictable
   */
  protected String genSessionId() {
    // We generate some random bytes and then convert to ASCII.
    //
    // We synchronize on randomBytes so as to singlethread access
    // to 'randomBytes', and 'sidBuilder'.
    synchronized (randomBytes) {
      random.nextBytes(randomBytes);
      sidBuilder.setLength(0);
      Formatter f = new Formatter(sidBuilder);
      for (byte b : randomBytes) {
        f.format("%02x", b);
      }
      return f.toString();
    }
  }

  /**
   * Run session garbage stochastically (i.e. ~1% chance upon call to this func).
   */
  protected void garbageCollectIfNeeded() {
    if (random.nextDouble() < 0.01) {
      garbageCollectNow();
    }
  }

  /**
   * Allows for dependency injection for the backend. If the parameter is
   * null, it selects a default one based on command-line parameters.
   *
   * @param backend
   */
  protected void setupBackendBase(BackendInterfaceBase backend) {
    if (backend != null) {
      logger.fine("Using <" + backend.getClass() + "> as Session Manager backend.");
      this.backend = backend;
    } else {
      setupDefaultBackend();
    }
  }

  protected void setupDefaultBackend() {
    this.backend = new BackendFilesBase(settings);
  }

  @VisibleForTesting
  public BackendInterfaceBase getBackend() {
    return backend;
  }

  //-------------------------------------------------
  // CONSTRUCTOR

  public SessionManagerBase() {
    // Will use the default backend.
    this(null);
  }
  /**
   * Allows for dependency injection for the backend (used mainly for tests).
   *
   * @param backend Desired backend - overrides the default.
   */
  public SessionManagerBase(BackendInterfaceBase backend) {
    settings = new Settings();
    setupBackendBase(backend);
  }

  // -------------------------------------------------
  // INTERFACE SPECIFIED METHODS

  /** @see com.google.enterprise.sessionmanager.SessionManagerInterface#sessionExists */
  @Override
  public boolean sessionExists(String sessionId) {
    if (sessionId == null || sessionId.equals("")) {
      return false;
    }

    return backend.sessionExists(sessionId);
  }

  /**
   * @see com.google.enterprise.sessionmanager.SessionManagerInterface#keyExists
   */
  public boolean keyExists(String sessionId, String key) {
    return backend.keyExists(sessionId, key);
  }

  /**
   * @see com.google.enterprise.sessionmanager.SessionManagerInterface#sessionAge
   */
  public long sessionAge(String sessionId) {
    return backend.sessionAge(sessionId);
  }

  /**
   * @see com.google.enterprise.sessionmanager.SessionManagerInterface#createSession
   */
  public String createSession() {
    garbageCollectIfNeeded();

    String sessionId = genSessionId();
    backend.createSession(sessionId);
    return sessionId;
  }

  /**
   * @see com.google.enterprise.sessionmanager.SessionManagerInterface#setValue
   */
  public void setValue(String sessionId, String key, String newValue)
      throws IndexOutOfBoundsException {
    garbageCollectIfNeeded();

    if (newValue == null) {
      newValue = new String("");
    }

    logger.finer("session:" + sessionId + " key:" + key + " newValue:" + newValue);
    backend.writeData(sessionId, key, newValue);
  }

  /**
   * @see com.google.enterprise.sessionmanager.SessionManagerInterface#getValue
   */
  public String getValue(String sessionId, String key)
      throws IndexOutOfBoundsException {
    garbageCollectIfNeeded();

    if (key == null)
        return null;
    byte[] data = backend.readKey(sessionId, key);
    if (data == null) {
        logger.finer("session:" + sessionId + " key:" + key + ".  Not Present.");
        return null;
    }
    String value = Utils.toStringUtf8(data);

    logger.finer("session:" + sessionId + " key:" + key + " value:" + value);
    return value;
  }

  public void setValueBin(String sessionId, String key, byte[] newValue)
      throws IndexOutOfBoundsException {
    garbageCollectIfNeeded();

    if (newValue == null) {
      newValue = new byte[0];
    }

    logger.finer("session:" + sessionId
              + " key:" + key
              + " newValue:" + Utils.toStringUtf8(newValue));
    backend.writeData(sessionId, key, newValue);
  }

  public void setValueCompressed(String sessionId, String key, byte[] value)
      throws IndexOutOfBoundsException {
    garbageCollectIfNeeded();

    if (value == null) {
      value = new byte[0];
    }

    logger.finer("session:" + sessionId
              + " key:" + key
              + " newValue:" + Utils.toStringUtf8(value)
              + " size:" + value.length);
    backend.writeCompressedData(sessionId, key, value);
  }

  public byte[] getValueBin(String sessionId, String key)
      throws IndexOutOfBoundsException {
    garbageCollectIfNeeded();

    if (key == null) return null;

    byte[] result = backend.readKey(sessionId, key);
    logger.finer("session:" + sessionId
              + " key:" + key
              + " result: " + Utils.toStringUtf8(result));
    return result;
  }

  /**
   * @see com.google.enterprise.sessionmanager.SessionManagerInterface#storeKrb5Identity
   */
  public KerberosId storeKrb5Identity(String sessionId, String spnegoBlob)
    throws IndexOutOfBoundsException {
    garbageCollectIfNeeded();

    logger.finer("session:" + sessionId + " blob length:" + spnegoBlob.length());
    return backend.storeKrb5Identity(sessionId, spnegoBlob);
  }

  /**
   * @see com.google.enterprise.sessionmanager.SessionManagerInterface#getKrb5TokenForServer
   */
  public KeyMaterial getKrb5TokenForServer(String sessionId, String server)
    throws IndexOutOfBoundsException {
    garbageCollectIfNeeded();

    logger.finer("session:" + sessionId + " server" + server);
    return backend.getKrb5TokenForServer(sessionId, server);
  }

  /**
   * @see com.google.enterprise.sessionmanager.SessionManagerInterface#getKrb5Identity
   */
  public String getKrb5Identity(String sessionId)
    throws IndexOutOfBoundsException {
    garbageCollectIfNeeded();

    logger.finer("session:" + sessionId + " user credentials are initialized?");
    return backend.getKrb5Identity(sessionId);
  }


 /**
   * @see com.google.enterprise.sessionmanager.SessionManagerInterface#deleteSession
   */
  public void deleteSession(String sessionId) throws IndexOutOfBoundsException {
    backend.deleteSession(sessionId);
    garbageCollectIfNeeded();
  }


  /**
   * @see com.google.enterprise.sessionmanager.SessionManagerInterface#getKrb5CcacheFilename
   */
  public String getKrb5CcacheFilename(String sessionId) throws IndexOutOfBoundsException {
    garbageCollectIfNeeded();
    return backend.getKrb5CcacheFilename(sessionId);
  }

  /**
   * @see com.google.enterprise.sessionmanager.SessionManagerInterface#parseKrb5Keytab
   */
  public String parseKrb5Keytab(String filepath) {
    garbageCollectIfNeeded();
    return backend.parseKrb5Keytab(filepath);
  }

  /**
   * @see com.google.enterprise.sessionmanager.SessionManagerInterface#getKrb5ServerNameIfEnabled
   */
  public String getKrb5ServerNameIfEnabled() {
    garbageCollectIfNeeded();
    return backend.getKrb5ServerNameIfEnabled();
  }


  //-------------------------------------------------
  // ADDED PUBLIC METHODS SPECIFIC TO THIS IMPLEMENTATION
  // (these generally support testing)


  /**
   * wipe all data from the session back-end
   * (generally used for post-testing cleanup)
   */
  public void wipeAllSessionData() throws IndexOutOfBoundsException {
    List<String> sessions = backend.listSessions();
    for (String session : sessions) {
      backend.deleteSession(session);
    }
  }

  protected void garbageCollectNow() {
    List<String> sessions = null;
    try {
        sessions = backend.listSessions();
    } catch (Exception e){

      // RPC server thows exception for this method, we don't need to do
      // garbage collection as the server code itself does it.
      return;
    }
    if (sessions == null)
      return;
    for (String session : sessions) {

      // I've received reports that sometimes the call below to sessionAge
      // throws the session not found exception.  I'm not sure how listSessions
      // would return a sessionId that doesn't actually exist, perhaps some
      // funky race condition.  regardless, it's obviously best to wrap the
      // call to sessionAge in a try..catch ...  - ken2
      try {
        if (backend.sessionAge(session) > settings.getSessionTimeout()) {
          backend.deleteSession(session);
        }
      } catch (IndexOutOfBoundsException e) {
        // no need to take any action - if the session has ceased to exist,
        // we don't need to garbage collect it.
      }
    }
  }
}
