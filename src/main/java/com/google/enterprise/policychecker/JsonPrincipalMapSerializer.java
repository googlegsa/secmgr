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
import com.google.protobuf.util.JsonFormat;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Serializes a group to members map to/from Strings, files, and Readers. Json based.
 */
public class JsonPrincipalMapSerializer extends AbstractFileSerializer<GroupMembersMap>
    implements Serializer<GroupMembersMap> {
  private static final Logger logger =
      Logger.getLogger(JsonPrincipalMapSerializer.class.getName());

  public JsonPrincipalMapSerializer() {
  }

  /**
   * Using json, write each sub group as a entry to the GroupMembersMap entry.
   */
  @Override
  public void writeToFile(final GroupMembersMap groups, String filename) throws IOException {
    try (Writer writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(filename),
        UTF_8))) {
      AclGroups.Builder aclGroupsBuilder = AclGroups.newBuilder();
      for (Map.Entry<AclPrincipal, Set<AclPrincipal>> entry : groups.entrySet()) {
        aclGroupsBuilder.addMembership(AclGroup.newBuilder()
              .setPrincipal(entry.getKey())
              .addAllMembers(entry.getValue()));
      }
      writer.write(JsonFormat.printer().omittingInsignificantWhitespace()
        .print(aclGroupsBuilder.build()));
    }
  }

  @Override
  public GroupMembersMap parseFromFile(String filename) throws IOException {
    AclGroups.Builder aclGroupsBuilder = AclGroups.newBuilder();
    try (Reader reader = new BufferedReader(new InputStreamReader(new FileInputStream(filename),
        UTF_8))) {
      JsonFormat.parser().merge(reader, aclGroupsBuilder);
      AclGroups aclGroups = aclGroupsBuilder.build();
      GroupMembersMap.Builder builder = GroupMembersMap.builder();

      long numGroupsRead = 0;
      for (AclGroup group : aclGroups.getMembershipList()) {
        if (group.getPrincipal().getScope() != AclPrincipal.SCOPE.GROUP) {
          throw new IllegalArgumentException("AclGroup not well-formed: " + group);
        }
        builder.put(group);
        numGroupsRead++;
      }

      long numBytes = new File(filename).length();
      GroupMembersMap groupMap = builder.build();
      long numUniqueGroups = groupMap.size();
      logger.log(Level.INFO,
        "Groups reloaded - number of unique non-empty group definitions: {0}",
        numUniqueGroups);
      logger.log(Level.FINE, "parsed group members map; file size bytes: {0};"
          + " num group definitions read {1}; num unique non-empty group definitions {2}",
          new Object[] { numBytes, numGroupsRead, numUniqueGroups });
      return groupMap;
    }
  }

  /**
   * We do not support to convert from the group to members map to string yet.
   */
  @Override
  public String toString(GroupMembersMap groups) {
    throw new UnsupportedOperationException();
  }

  /**
   * We do not support to convert from string to the group to members map yet.
   */
  @Override
  public GroupMembersMap fromString(String s) {
    throw new UnsupportedOperationException();
  }

  /**
   * We do not support to convert from Reader to the group to members map yet.
   */
  @Override
  public GroupMembersMap parseFromReader(Reader reader) {
    throw new UnsupportedOperationException();
  }
}
