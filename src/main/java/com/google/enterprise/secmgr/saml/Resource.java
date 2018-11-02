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

import com.google.enterprise.secmgr.common.AuthzStatus;
import java.net.URI;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import org.opensaml.saml.common.SAMLObject;

/**
 * A SAML extension added to AuthzDecisionQuery messages by the GSA.
 */
@ParametersAreNonnullByDefault
public interface Resource extends SAMLObject {
  public static final QName DEFAULT_ELEMENT_NAME
      = new QName(OpenSamlUtil.GOOGLE_NS_URI, "Resource", OpenSamlUtil.GOOGLE_NS_PREFIX);
  public static final QName URI_ATTRIB_NAME
      = new QName(XMLConstants.NULL_NS_URI, "uri", XMLConstants.DEFAULT_NS_PREFIX);
  public static final QName DECISION_ATTRIB_NAME
      = new QName(XMLConstants.NULL_NS_URI, "decision", XMLConstants.DEFAULT_NS_PREFIX);
  public static final QName ACL_ATTRIB_NAME
      = new QName(XMLConstants.NULL_NS_URI, "acl", XMLConstants.DEFAULT_NS_PREFIX);

  @Nonnull
  public URI getUri();

  @Nullable
  public AuthzStatus getDecision();

  @Nullable
  public String getAcl();

  public void setUri(URI uri);

  public void setDecision(@Nullable AuthzStatus decision);

  public void setAcl(@Nullable String acl);
}
