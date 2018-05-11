// Copyright 2009 Google Inc.
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

import com.google.common.collect.ImmutableList;
import com.google.common.labs.matcher.UrlMapping;
import com.google.enterprise.supergsa.security.PolicyAcl;

public class CompactUrlAclMap extends UrlAclMap {

  public CompactUrlAclMap() {
    super(new Group("everyone"),
        new UrlMapping<Acl>(new CompactUrlMapperCollectionFactory<Acl>()), null);
  }

  @Override
  public void put(String patternString, Acl acl) {
    Acl oldAcl = mapping.getByPattern(patternString);
    if (oldAcl == acl) {
      return;
    }
    mapping.put(patternString, acl);
  }

  @Override
  public Acl getAclForPattern(String pattern) {
    return mapping.getByPattern(pattern);
  }

  @Override
  public ImmutableList<PolicyAcl> getAllMappingsByMetapattern(String metapattern) {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean removePattern(String pattern) {
    mapping.remove(pattern);
    return true;
  }
}
