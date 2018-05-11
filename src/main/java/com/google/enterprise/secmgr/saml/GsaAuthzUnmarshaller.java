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

import com.google.enterprise.secmgr.common.XmlUtil;
import org.opensaml.common.impl.AbstractSAMLObjectUnmarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;

/** An unmarshaller (XML to object converter) for {@link GsaAuthz}. */
final class GsaAuthzUnmarshaller extends AbstractSAMLObjectUnmarshaller {

  @Override
  public XMLObject unmarshall(Element domElement)
      throws UnmarshallingException {
    GsaAuthz object = (GsaAuthz) super.unmarshall(domElement);
    try {
      object.getVersion();
      object.getMode();
    } catch (IllegalStateException e) {
      throw new UnmarshallingException(e);
    }
    return object;
  }

  @Override
  protected void processAttribute(XMLObject xmlObject, Attr attribute)
      throws UnmarshallingException {
    GsaAuthz object = (GsaAuthz) xmlObject;
    if (XmlUtil.attributeHasQname(attribute, GsaAuthz.VERSION_ATTRIB_NAME)) {
      try {
        object.setVersion(Integer.parseInt(attribute.getValue()));
      } catch (NumberFormatException e) {
        throw new UnmarshallingException(e);
      } catch (IllegalArgumentException e) {
        throw new UnmarshallingException(e);
      }
    } else if (XmlUtil.attributeHasQname(attribute, GsaAuthz.MODE_ATTRIB_NAME)) {
      try {
        object.setMode(GsaAuthz.Mode.valueOf(attribute.getValue()));
      } catch (IllegalArgumentException e) {
        throw new UnmarshallingException(e);
      }
    }
  }
}
