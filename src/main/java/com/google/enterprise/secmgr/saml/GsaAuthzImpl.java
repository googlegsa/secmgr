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

import org.opensaml.common.impl.AbstractSAMLObject;
import org.opensaml.xml.XMLObject;

import java.util.List;

import javax.annotation.ParametersAreNonnullByDefault;

/** An implementation for {@link GsaAuthz}. */
@ParametersAreNonnullByDefault
final class GsaAuthzImpl extends AbstractSAMLObject implements GsaAuthz {
  private int version;
  private Mode mode;

  GsaAuthzImpl(String nsUri, String localName, String nsPrefix) {
    super(nsUri, localName, nsPrefix);
  }

  @Override
  public int getVersion() {
    Preconditions.checkState(version >= MIN_VERSION && version <= MAX_VERSION,
        "Illegal version: %d", version);
    return version;
  }

  @Override
  public Mode getMode() {
    return mode;
  }

  @Override
  public void setVersion(int version) {
    Preconditions.checkArgument(version >= MIN_VERSION && version <= MAX_VERSION,
        "Illegal version: %d", version);
    this.version = version;
  }

  @Override
  public void setMode(Mode mode) {
    this.mode = mode;
  }

  @Override
  public List<XMLObject> getOrderedChildren() {
    // This object has no child elements.
    return ImmutableList.of();
  }
}
