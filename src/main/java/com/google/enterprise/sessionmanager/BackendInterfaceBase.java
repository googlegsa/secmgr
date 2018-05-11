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

import java.util.List;

/**
 * This interface provides an abstracton layer between the general functionality
 * of the session manager and the storage mechanism it uses as a back end.
 * We know that the at least two back-ends will be implemented - simple files
 * in /tmp/ and Chubby-based storage in /ls/, so this provides a simple point
 * to separate those implementations
 *
 *
 * TODO - add well-thought through exceptions for failure conditions
 */
public interface BackendInterfaceBase {

  /**
   * indicate whether a session ID exists within the storage back-end
   *
   * @param sessionId
   * @return        true if the session exists
   */
  boolean sessionExists(String sessionId);

  /**
   * indicate whether a key exists within session
   *
   * @param sessionId
   * @param key
   * @return        true if the key exists
   */
  boolean keyExists(String sessionId, String key);

  /**
   * returns the age of a session - i.e. the number of seconds since the
   * last read or write for any key in that session
   *
   * @throws        IndexOutOfBoundsException if session doesn't exist
   */
  long sessionAge(String sessionId);


  /**
   * creates an empty session in the back-end.
   *
   * @throws        RuntimeException if unable to create session
   */
  public void createSession(String sessionId);

  /**
   * remove a given session from the backend
   */
  void deleteSession(String sessionId);

  /**
   * retrieve a key's data
   *
   * @return            the contents of the key within the session or null if
   *                    the key doesn't exist (but the session does)
   * @throws            IndexOutOfBoundsException if the key session
   *                    does not exist
   */
  byte[] readKey(String sessionId, String key);

  /**
   * write data to the back-end
   *
   * @param sessionId
   * @param key         keyname to create or update
   * @param contents    the contents to save to this key within this session
   * @throws            IndexOutOfBoundsException if the session doesn't exist
   * @throws            RuntimeException if the operation fails
   */
  void writeData(String sessionId, String key, byte[] contents);

  void writeData(String sessionId, String key, String value);

  void writeCompressedData(String sessionId, String key, byte[] contents);

  /**
   * enumerate the stored sessions
   */
  List<String> listSessions();

  /**
   * enumerate the keys within a session
   */
  List<String> listKeys(String sessionId);

  /**
   * pass an SPNEGO/Kerberos token to the Session Manager so that it extracts
   * the delegated user identity for use in subsequent Head Requests
   * @param sessionId
   * @param spnegoBlob  SPNEGO/Kerberos token fetched from the client
   * @return            Kerberos identity if the operation completed
   *                    successfully, null otherwise
   */
  public KerberosId storeKrb5Identity(String sessionId, String spnegoBlob);

  /**
   * request an Kerberos KeyMaterial object based on the currently Kerberos
   * identity associated with the session
   * @param sessionId
   * @param server      Target server name
   * @return            KeyMaterial object with the relevant token, key pair
   */
  public KeyMaterial getKrb5TokenForServer(String sessionId, String server);

  /**
   * Returns the Kerberos identity if it has been initialized.
   * @param sessionId
   * @return            A non-null string with the Kerberos identity if the
   *                    credentials have been properly initialized for
   *                    delegation. Null otherwise.
   * @throws            IndexOutOfBoundsException if the sessionId given is not
   *                    an existing sessionId
   */
  public String getKrb5Identity(String sessionId);

  /**
   * Returns the path to the Kerberos Credentials Cache where the user
   * credentials are stored.
   * @param sessionId
   * @return            Credentials Cache filename.
   * @throws            IndexOutOfBoundsException if the sessionId given is not
   *                    an existing sessionId
   */
  public String getKrb5CcacheFilename(String sessionId);

  /**
   * Parses the given keytab filename.
   * @return           Principal name inside the first entry in the keytab
   *                   file on success, null otherwise.
   * @throws           RuntimeException if not implemented.
   */
  public String parseKrb5Keytab(String filepath);

  /**
   * Gets the server principal name.
   * @return           Server principal name if the Kerberos engine has been
   *                   initialized, null otherwise.
   * @throws           RuntimeException if not implemented.
   */
  public String getKrb5ServerNameIfEnabled();

}
