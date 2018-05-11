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
package com.google.enterprise.secmgr.authncontroller;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.enterprise.supergsa.security.AclPrincipals;
import com.google.protobuf.util.JsonFormat;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;

/**
 * Serialize/deserialize AclPrincipal list using json format
 */
public class AclPrincipalStoreRecordJsonBased implements AclPrincipalStore {

  @Override
  public Set<AclPrincipal> load(String filename) throws IOException {
    try (Reader reader = Files.newBufferedReader(Paths.get(filename), UTF_8)) {
      AclPrincipals.Builder aclPrincipals = AclPrincipals.newBuilder();
      JsonFormat.parser().merge(reader, aclPrincipals);
      return new HashSet<>(aclPrincipals.getPrincipalsList());
    }
  }

  @Override
  public void store(AclPrincipals aclPrincipals, String filename) throws IOException {
    try (Writer writer = Files.newBufferedWriter(Paths.get(filename), UTF_8)) {
      writer.write(JsonFormat.printer().print(aclPrincipals));
    }
  }

  public AclPrincipalStoreRecordJsonBased() {
  }
}
