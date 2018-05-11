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

import com.google.enterprise.supergsa.security.AclGroup;
import com.google.enterprise.supergsa.security.AclGroups;
import com.google.enterprise.supergsa.security.AclPrincipal;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;

/**
 * Serializes Principals to/from Strings, files, and Readers. Json based.
 */
public class JsonPrincipalSerializer extends AbstractFileSerializer<Principal>
    implements Serializer<Principal> {

  public JsonPrincipalSerializer() {
  }

  @Override
  public String toString(Principal principal) {
    if (principal == null) {
      return null;
    }
    if (principal instanceof User) {
      // We don't have to worry about Users.
      throw new UnsupportedOperationException();
    } else {
      try {
        return JsonFormat.printer().omittingInsignificantWhitespace()
            .print(((Group) principal).toAclGroup());
      } catch (InvalidProtocolBufferException e) {
        throw new RuntimeException(e);
      }
    }
  }

  @Override
  public Principal fromString(String s) {
    if (s == null) {
      return null;
    }
    AclGroup.Builder builder = AclGroup.newBuilder();
    try {
      JsonFormat.parser().merge(s, builder);
      return Group.fromAclGroup(builder.build());
    } catch (InvalidProtocolBufferException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Write each sub group as a log entry, omitting the top-level users and top-level group name.
   */
  @Override
  public void writeToFile(final Principal group, String filename) throws IOException {

    if (!(group instanceof Group)) {
      throw new IllegalArgumentException("argument " + group + " not a Group");
    }

    Group typedGroup = (Group) group;

    try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(filename),
        UTF_8))) {

      AclGroups.Builder groups = AclGroups.newBuilder();
      for (AclPrincipal groupId : typedGroup.getDirectAclPrincipalGroups()) {
        Group subGroup = typedGroup.getGroup(groupId);
        groups.addMembership(subGroup.toAclGroup());
      }
      writer.write(JsonFormat.printer().omittingInsignificantWhitespace()
          .print(groups.build()));
    }
  }

  @Override
  public Group parseFromReader(Reader reader) {
    throw new UnsupportedOperationException();
  }

  @Override
  public Group parseFromFile(String filename) throws IOException {
    Group group = new Group("everyone");

    AclGroups.Builder aclGroupsBuilder = AclGroups.newBuilder();
    try (Reader reader = new BufferedReader(new InputStreamReader(new FileInputStream(filename),
        UTF_8))) {
      JsonFormat.parser().merge(reader, aclGroupsBuilder);
      for (AclGroup subGroup : aclGroupsBuilder.getMembershipList()) {
        group.addGroup(Group.fromAclGroup(subGroup));
      }
    }
    return group;
  }
}
