// Copyright 2012 Google Inc. All Rights Reserved.
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

import static java.util.concurrent.TimeUnit.MILLISECONDS;

import com.google.common.base.Stopwatch;
import com.google.enterprise.supergsa.security.PolicyAcl;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.util.List;
import java.util.Stack;
import java.util.logging.Logger;

/**
 * Serializes UrlAclMaps to/from files and Readers.
 *
 */
public class PlainTextUrlAclMapSerializer extends AbstractFileSerializer<UrlAclMap> implements
    FileSerializer<UrlAclMap> {

  private static final Logger logger =
      Logger.getLogger(PlainTextUrlAclMapSerializer.class.getName());

  // Needed for serializing the ACL lines themselves.
  private final Serializer<Acl> aclSerializer;

  public PlainTextUrlAclMapSerializer() {
    this(null);
  }

  public PlainTextUrlAclMapSerializer(Group group) {
    aclSerializer = new PlainTextAclSerializer(group);
  }

  @Override
  public void writeToFile(UrlAclMap urlAclMap, String filename) throws IOException {
    Stopwatch watch = Stopwatch.createStarted();
    BufferedWriter aclWriter = new BufferedWriter(new FileWriter(filename));
    logger.info("Took " + watch.elapsed(MILLISECONDS) + " ms to open file");
    List<PolicyAcl> s = urlAclMap.getAllMappingsByMetapattern("");
    logger.info("Took " + watch.elapsed(MILLISECONDS) + " ms to get ACLs");
    for (PolicyAcl entry : s) {
      aclWriter.write(entry.getPattern());
      aclWriter.write(" ");
      aclWriter.write(Acl.fromGsaAcl(entry.getAcl()).toString());
      aclWriter.write("\n");
    }

    aclWriter.flush();
    watch.stop();
    logger.info("Took " + watch.elapsed(MILLISECONDS) + " ms to flush to disk");
    aclWriter.close();
  }

  @Override
  public UrlAclMap parseFromReader(Reader reader) throws IOException {
    BufferedReader br = makeBufferedReader(reader);
    UrlAclMap aclMap = new UrlAclMap();
    addUrlMappingsFromPlainText(aclMap, br);
    return aclMap;
  }

  private void addUrlMappingsFromPlainText(UrlAclMap urlAclMap,
      BufferedReader bufferedReader) {
    String line = null;
    while ((line = Utils.readLine(bufferedReader)) != null) {
      addSingleUrlMappingFromPlainText(urlAclMap, line);
    }
  }

  private void addSingleUrlMappingFromPlainText(UrlAclMap urlAclMap, String s) {
    Stack<String> tokens = Utils.splitOffUrl(s);
    if (tokens.isEmpty()) {
      throw new IllegalArgumentException("No URL in tokens");
    }
    String url = tokens.pop();
    if (tokens.isEmpty()) {
      throw new IllegalArgumentException("No ACL string in tokens");
    }
    String aclString = tokens.pop();
    Acl acl = aclSerializer.fromString(aclString);
    urlAclMap.put(url, acl);
  }
}
