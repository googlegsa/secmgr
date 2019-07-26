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

import javax.annotation.Nonnull;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import org.opensaml.saml.common.SAMLObject;

/**
 * A SAML extension added to AuthnRequest messages by the GSA.
 */
@ParametersAreNonnullByDefault
public interface GsaAuthn extends SAMLObject {
  public static final QName DEFAULT_ELEMENT_NAME
      = new QName(OpenSamlUtil.GOOGLE_NS_URI, "GsaAuthn", OpenSamlUtil.GOOGLE_NS_PREFIX);
  public static final QName VERSION_ATTRIB_NAME
      = new QName(XMLConstants.NULL_NS_URI, "version", XMLConstants.DEFAULT_NS_PREFIX);
  public static final QName SESSION_ID_ATTRIB_NAME
      = new QName(XMLConstants.NULL_NS_URI, "sessionId", XMLConstants.DEFAULT_NS_PREFIX);

  public static final int MIN_VERSION = 1;
  public static final int CURRENT_VERSION = 1;
  public static final int MAX_VERSION = CURRENT_VERSION;

  public int getVersion();

  public void setVersion(int version);

  @Nonnull
  public String getSessionId();

  public void setSessionId(String sessionId);
}
