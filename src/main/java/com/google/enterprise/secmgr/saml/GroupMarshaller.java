/*
 * Copyright 2014 Google Inc.
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

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.AbstractSAMLObjectMarshaller;
import org.w3c.dom.Element;

/** A marshaller (object to XML converter) for {@link Group}. */
final class GroupMarshaller extends AbstractSAMLObjectMarshaller {
  @Override
  protected void marshallAttributes(XMLObject xmlObject, Element domElement) {
    Group object = (Group) xmlObject;
    XMLObjectSupport.marshallAttribute(Group.NAME_ATTRIB_NAME, object.getName(), domElement, false);
    XMLObjectSupport.marshallAttribute(
        Group.NAMESPACE_ATTRIB_NAME, object.getNamespace(), domElement, false);
    if (object.getDomain() != null) {
      XMLObjectSupport.marshallAttribute(
          Group.DOMAIN_ATTRIB_NAME, object.getDomain(), domElement, false);
    }
  }
}
