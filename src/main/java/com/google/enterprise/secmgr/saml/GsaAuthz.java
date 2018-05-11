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

import org.opensaml.common.SAMLObject;

import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;

/**
 * A SAML extension added to AuthzDecisionQuery messages by the GSA.
 */
@ParametersAreNonnullByDefault
public interface GsaAuthz extends SAMLObject {
  public static final QName DEFAULT_ELEMENT_NAME
      = new QName(OpenSamlUtil.GOOGLE_NS_URI, "GsaAuthz", OpenSamlUtil.GOOGLE_NS_PREFIX);
  public static final QName VERSION_ATTRIB_NAME
      = new QName(XMLConstants.NULL_NS_URI, "version", XMLConstants.DEFAULT_NS_PREFIX);
  public static final QName MODE_ATTRIB_NAME
      = new QName(XMLConstants.NULL_NS_URI, "mode", XMLConstants.DEFAULT_NS_PREFIX);

  public static final int MIN_VERSION = 2;
  public static final int CURRENT_VERSION = 2;
  public static final int MAX_VERSION = CURRENT_VERSION;

  /**
   * Request mode; FAST says just use in-memory mechanisms, otherwise use ALL
   * mechanisms.
   */
  public enum Mode { ALL, FAST }

  public int getVersion();

  @Nullable
  public Mode getMode();

  public void setVersion(int version);

  public void setMode(@Nullable Mode mode);
}
