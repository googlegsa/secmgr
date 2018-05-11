/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.enterprise.secmgr.saml;

import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.common.AuthzStatus;

import org.opensaml.common.impl.AbstractSAMLObject;
import org.opensaml.xml.XMLObject;

import java.net.URI;
import java.util.List;

import javax.annotation.ParametersAreNonnullByDefault;

/** An implementation for {@link Resource}. */
@ParametersAreNonnullByDefault
final class ResourceImpl extends AbstractSAMLObject implements Resource {
  private URI uri;
  private AuthzStatus decision;
  private String acl;

  ResourceImpl(String nsUri, String localName, String nsPrefix) {
    super(nsUri, localName, nsPrefix);
  }

  @Override
  public URI getUri() {
    Preconditions.checkState(uri != null, "URI must be non-null");
    return uri;
  }

  @Override
  public AuthzStatus getDecision() {
    return decision;
  }

  @Override
  public String getAcl() {
    return acl;
  }

  @Override
  public void setUri(URI uri) {
    Preconditions.checkArgument(uri != null, "URI must be non-null");
    this.uri = uri;
  }

  @Override
  public void setDecision(AuthzStatus decision) {
    this.decision = decision;
  }

  @Override
  public void setAcl(String acl) {
    this.acl = acl;
  }

  @Override
  public List<XMLObject> getOrderedChildren() {
    // This object has no child elements.
    return ImmutableList.of();
  }
}
