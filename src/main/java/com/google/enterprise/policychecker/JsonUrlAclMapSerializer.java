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

package com.google.enterprise.policychecker;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.enterprise.supergsa.security.PolicyAcl;
import com.google.enterprise.supergsa.security.PolicyAcls;
import com.google.protobuf.util.JsonFormat;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;

/**
 * UrlAclMap file json based serializer.
 */
public class JsonUrlAclMapSerializer extends AbstractUrlAclMapSerializer {

  private final Group group;

  public JsonUrlAclMapSerializer() {
    group = null;
  }

  public JsonUrlAclMapSerializer(Group group) {
    this.group = group;
  }

  @Override
  public void writeToFile(UrlAclMap urlAclMap, String filename) throws IOException {
    writeToStream(urlAclMap, new FileOutputStream(filename));
  }

  public void writeToStream(UrlAclMap urlAclMap, OutputStream stream) throws IOException {
    try (Writer writer = new BufferedWriter(new OutputStreamWriter(stream, UTF_8))) {
      PolicyAcls.Builder policyAclsBuilder = PolicyAcls.newBuilder();
      for (PolicyAcl acl : urlAclMap.getAllMappingsByMetapattern("")) {
        policyAclsBuilder.addAcls(acl);
      }
      writer.write(JsonFormat.printer().omittingInsignificantWhitespace()
          .print(policyAclsBuilder.build()));
    }
  }

  @Override
  public UrlAclMap parseFromReader(Reader reader) throws IOException {
    throw new UnsupportedOperationException();
  }

  @Override
  public UrlAclMap parseFromFile(String filename) throws IOException {
    return parseFromStream(new FileInputStream(filename));
  }

  @Override
  public UrlAclMap parseFromStream(InputStream stream) throws IOException {
    PolicyAcls.Builder builder = PolicyAcls.newBuilder();
    try (Reader reader = new BufferedReader(new InputStreamReader(stream, UTF_8))) {
      JsonFormat.parser().merge(reader, builder);
      PolicyAcls policyAcls = builder.build();
      UrlAclMap aclMap = new UrlAclMap();
      for (PolicyAcl acl : policyAcls.getAclsList()) {
        aclMap.addPattern(acl.getPattern(), Acl.fromGsaAcl(acl.getAcl(), group));
      }
      return aclMap;
    }
  }
}
