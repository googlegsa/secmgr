// Copyright 2009 Google Inc.
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

package com.google.enterprise.secmgr.saml;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.AbstractSAMLObjectMarshaller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

// This class should be part of OpenSAML but is missing from there.
public class AttributeValueMarshaller
    extends AbstractSAMLObjectMarshaller {
  @Override
  protected void marshallElementContent(XMLObject xmlObject, Element domElement)
      throws MarshallingException {
    appendTextContent(domElement, ((AttributeValueImpl) xmlObject).getValue());
  }

  /**
   * From OpenSAML 2
   */
  private static void appendTextContent(Element domElement, String textContent) {
    if (textContent == null) {
      return;
    }
    Document parentDocument = domElement.getOwnerDocument();
    Text textNode = parentDocument.createTextNode(textContent);
    domElement.appendChild(textNode);
  }
}
