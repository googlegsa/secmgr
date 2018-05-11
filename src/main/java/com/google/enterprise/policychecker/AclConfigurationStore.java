// Copyright 2012 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.enterprise.policychecker;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class is responsible for handling the saving and loading of the
 * AclConfiguration to a file.
 *
 * The AclConfigurationStore tries to make saves happen atomically by writing
 * the Acl and Groups files to a temp file first and then renaming the file to
 * the actual filename when it is done.
 */
public class AclConfigurationStore {

  private static final Logger logger = Logger.getLogger(AclConfigurationStore.class.getName());

  private static final String TEMP_EXTENSION = ".temp";

  private UrlAclMap aclMap;
  private Group groups;
  private final String aclFile;
  private final String groupsFile;

  public AclConfigurationStore(UrlAclMap aclMap, String aclFilename,
      String groupsFilename) {
    this.aclMap = aclMap;
    this.aclFile = aclFilename;
    this.groupsFile = groupsFilename;
  }

  public UrlAclMap getAclMap() {
    return aclMap;
  }

  /**
   * Returns an immutable view of the groups.
   */
  public ImmutableGroup getImmutableGroups() {
    return new ImmutableGroup(groups);
  }

  /**
   * Reads acls and groups from the specified files
   *
   * @throws FileNotFoundException if the acl file is not found. A missing
   *         groups file is logged and remembered, but no exception is thrown.
   */
  public void reloadConfiguration() throws FileNotFoundException {
    readGroups();
    readAcls();
  }

  public void resetAclsFromReader(Reader reader) {
    PlainTextUrlAclMapSerializer serializer = new PlainTextUrlAclMapSerializer(groups);
    try {
      aclMap = serializer.parseFromReader(reader);
    } catch (IOException e) {
      logger.log(Level.WARNING, "Problem reading policy ACLs: " + aclFile, e);
    }
  }

  public void resetAclsFromStream(InputStream stream) {
    AbstractUrlAclMapSerializer serializer = UrlAclMapSerializerFactory.create(groups);
    try {
      aclMap = serializer.parseFromStream(stream);
    } catch (IOException e) {
      logger.log(Level.WARNING, "Problem reading policy ACLs: " + aclFile, e);
    }
  }

  private void readAcls() {
    FileSerializer<UrlAclMap> serializer = UrlAclMapSerializerFactory.create(groups);
    try {
      aclMap = serializer.parseFromFile(aclFile);
    } catch (IOException e) {
      logger.log(Level.WARNING, "Problem parsing policy ACLs: " + aclFile, e);
    }
  }

  private void readGroups() {
    FileSerializer<Principal> serializer = PrincipalSerializerFactory.create();
    try {
      groups = (Group) serializer.parseFromFileAndCatchFileNotFoundException(groupsFile);
    } catch (IOException e) {
      logger.log(Level.WARNING, "Problem parsing groups DB: " + groupsFile, e);
    }
  }

  public GroupMembersMap readGroupsIntoMap() {
    FileSerializer<GroupMembersMap> serializer = PrincipalMapSerializerFactory.create();
    try {
      return serializer.parseFromFileAndCatchFileNotFoundException(groupsFile);
    } catch (IOException e) {
      logger.log(Level.WARNING, "Problem parsing groups DB: " + groupsFile, e);
    }
    return null;
  }

  public boolean saveConfiguration() throws IOException {
    return saveConfiguration(false);
  }

  public boolean saveConfiguration(boolean force) throws IOException {
    if (!force && !aclMap.hasChanged()) {
      return false;
    }

    if (!saveAcls()) {
      return false;
    }

    if (!saveGroups()) {
      return false;
    }

    aclMap.resetHasChanged();
    return true;
  }

  private boolean saveAcls() throws IOException {
    FileSerializer<UrlAclMap> serializer = UrlAclMapSerializerFactory.create(groups);
    String aclTempFile = aclFile + TEMP_EXTENSION;
    serializer.writeToFile(aclMap, aclFile + TEMP_EXTENSION);

    if (rename(aclTempFile, aclFile)) {
      return true;
    }

    logger.warning("trouble renaming " + aclTempFile + " to " + aclFile);
    return false;
  }

  private boolean saveGroups() throws IOException {
    FileSerializer<Principal> serializer = PrincipalSerializerFactory.create();
    String groupsTempFile = groupsFile + TEMP_EXTENSION;
    serializer.writeToFile(aclMap.groups(), groupsTempFile);

    if (rename(groupsTempFile, groupsFile)) {
      aclMap.resetHasChanged();
      return true;
    }

    /** something went wrong during the rename */
    logger.warning("trouble renaming " + groupsTempFile + " to " + groupsFile);
    return false;
  }

  private boolean rename(String src, String dest) {
    File srcFile = new File(src);
    if (!srcFile.exists()) {
      return true;
    }
    File dstFile = new File(dest);
    boolean dstexists = dstFile.exists();
    if (dstexists) {
      dstFile.delete();
    }
    return srcFile.renameTo(dstFile);
  }
}
