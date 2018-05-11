// Copyright 2011 Google Inc.
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

package com.google.enterprise.secmgr.common;

import com.google.common.collect.ImmutableList;

import java.util.Collection;

/**
 * Class to represent an Authz Url and its acl decision.
 * 
 */
public class Resource {
  private final String resourceUrl;
  private final AuthzStatus priorAclDecision;
  
  public Resource(String url, AuthzStatus priorAclDecision) {
    resourceUrl = url;
    this.priorAclDecision = priorAclDecision;
  }
  
  public String getUrl() {
    return resourceUrl;
  }
  
  public AuthzStatus getPriorAclDecision() {
    return priorAclDecision;
  }

  /**
   * Gets a collection of resources from a collection of urls with no Acls.
   * @param urls collection of urls.
   * @return collection of resources.
   */
  public static Collection<Resource> urlsToResourcesNoAcls(Collection<String> urls) {
    ImmutableList.Builder<Resource> resources = ImmutableList.builder();
    for (String url : urls) {
      resources.add(new Resource(url, null));
    }
    return resources.build();
  }

  /**
   * Gets the urls in a list of Resources.
   * @param resources collection of resources.
   * @return collection of urls.
   */
  public static Collection<String> resourcesToUrls(Collection<Resource> resources) {
    ImmutableList.Builder<String> resourceUrls = ImmutableList.builder();
    for (Resource resource : resources) {
      resourceUrls.add(resource.getUrl());
    }
    return resourceUrls.build();
  }

}
