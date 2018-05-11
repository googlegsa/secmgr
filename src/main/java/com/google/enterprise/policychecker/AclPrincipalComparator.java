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

import com.google.enterprise.supergsa.security.AclPrincipal;

import java.util.Comparator;

/**
 * Comparator of AclPrincipal objects so we can build ImmutableSortedSets of them.
 *
 */
public class AclPrincipalComparator implements Comparator<AclPrincipal> {
  @Override
  public int compare(AclPrincipal a, AclPrincipal b) {
    if (a == null) {
      if (b == null) {
        return 0;
      }
      return -1;
    }
    if (b == null) {
      return 1;
    }
    int nameComparison = a.getName().compareTo(b.getName());
    if (nameComparison != 0) {
      return nameComparison;
    }
    // Ensure the equals contract is observed.
    if (a.equals(b)) {
      return 0;
    }
    return a.toString().compareTo(b.toString());
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof AclPrincipalComparator;
  }

  @Override
  public int hashCode() {
    return 1;
  }
}
