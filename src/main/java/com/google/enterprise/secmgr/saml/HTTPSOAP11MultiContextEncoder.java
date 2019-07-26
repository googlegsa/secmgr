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

import java.io.IOException;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.binding.encoding.SAMLMessageEncoder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
import org.w3c.dom.Element;

/**
 * SAML 2.0 SOAP 1.1 over HTTP MultiContext binding encoder. Based on OpenSaml's HTTPSOAP11Encoder
 */
public class HTTPSOAP11MultiContextEncoder extends HTTPSOAP11Encoder implements SAMLMessageEncoder {

  /** Constructor. */
  public HTTPSOAP11MultiContextEncoder() {
    super();
  }

  @Override
  public String getBindingURI() {
    return SAMLConstants.SAML2_SOAP11_BINDING_URI;
  }

  @Override
  protected String getSOAPAction() {
    return "http://www.oasis-open.org/committees/security";
  }

  @Override
  protected void doEncode() throws MessageEncodingException {
    // Do nothing here - the actual encoding is implemented in HTTPSOAP11Encoder.prepareContext()
    // Writing to the output is done by finish(), when all
  }

  public void finish() throws MessageEncodingException {
    Element envelopeElem = marshallMessage(getSOAPEnvelope());
    prepareHttpServletResponse();
    try {
      SerializeSupport.writeNode(envelopeElem, getHttpServletResponse().getOutputStream());
    } catch (IOException e) {
      throw new MessageEncodingException(
          "Problem writing SOAP envelope to servlet output stream", e);
    }
  }
}
