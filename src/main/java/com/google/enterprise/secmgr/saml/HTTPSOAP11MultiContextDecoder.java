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

import java.util.List;
import javax.annotation.Nonnull;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.handler.AbstractMessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;
import org.opensaml.soap.messaging.context.SOAP11Context;
import org.opensaml.soap.soap11.Envelope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SAML 2.0 SOAP 1.1 over HTTP MultiContext binding decoder. Based on OpenSaml's HTTPSOAP11Decoder
 */
public class HTTPSOAP11MultiContextDecoder extends HTTPSOAP11Decoder {

  /** Class logger. */
  private final Logger log = LoggerFactory.getLogger(HTTPSOAP11MultiContextDecoder.class);

  /** Constructor. */
  public HTTPSOAP11MultiContextDecoder() {
    super();
    setBodyHandler(new SAMLSOAPMultiContextDecoderBodyHandler());
  }

  /**
   * Constructor.
   *
   * @param pool parser pool used to deserialize messages
   */
  public HTTPSOAP11MultiContextDecoder(ParserPool pool) {
    this();
    setParserPool(pool);
  }

  /** {@inheritDoc} */
  @Override
  public String getBindingURI() {
    return SAMLConstants.SAML2_SOAP11_BINDING_URI;
  }

  /** {@inheritDoc} */
  @Override
  protected void doDecode() throws MessageDecodingException {
    super.doDecode();

    populateBindingContext(getMessageContext());

    SAMLObject samlMessage = getMessageContext().getMessage();
    log.debug(
        "Decoded SOAP messaged which included SAML message of type {}",
        samlMessage.getElementQName());
  }

  /**
   * Populate the context which carries information specific to this binding.
   *
   * @param messageContext the current message context
   */
  @Override
  protected void populateBindingContext(MessageContext<SAMLObject> messageContext) {
    SAMLBindingContext bindingContext =
        messageContext.getSubcontext(SAMLBindingContext.class, true);
    bindingContext.setBindingUri(getBindingURI());
    bindingContext.setHasBindingSignature(false);
    bindingContext.setIntendedDestinationEndpointURIRequired(false);
  }

  private static class SAMLSOAPMultiContextDecoderBodyHandler
      extends AbstractMessageHandler<SAMLObject> {

    /** Class logger. */
    @Nonnull
    private final Logger log =
        LoggerFactory.getLogger(SAMLSOAPMultiContextDecoderBodyHandler.class);

    private Envelope soapMessage;
    private List<XMLObject> soapBodyChildren;
    private int thisChild;

    @Override
    protected void doInvoke(@Nonnull MessageContext<SAMLObject> messageContext)
        throws MessageHandlerException {

      if (soapMessage == null) {
        start(messageContext);
      }

      if (soapBodyChildren.size() < 1) {
        log.error(
            "Unexpected number of children in the SOAP body, "
                + soapBodyChildren.size()
                + ".  Unable to extract SAML message");
        throw new MessageHandlerException(
            "Unexpected number of children in the SOAP body, unable to extract SAML message");
      }

      if (thisChild >= soapBodyChildren.size()) {
        // indicates to the caller that there are no more messages to decode
        // this should be caught and recovered from
        throw new IndexOutOfBoundsException();
      }

      final XMLObject incomingMessage = soapBodyChildren.get(thisChild);
      thisChild++;

      if (!(incomingMessage instanceof SAMLObject)) {
        log.error(
            "Unexpected SOAP body content.  Expected a SAML request but received {}",
            incomingMessage.getElementQName());
        throw new MessageHandlerException(
            "Unexpected SOAP body content.  Expected a SAML request but received "
                + incomingMessage.getElementQName());
      }

      SAMLObject samlMessage = (SAMLObject) incomingMessage;

      log.debug(
          "Decoded SOAP messaged which included SAML message of type {}",
          samlMessage.getElementQName());
      messageContext.setMessage(samlMessage);
    }

    private void start(MessageContext<SAMLObject> messageContext) throws MessageHandlerException {
      final SOAP11Context soap11Context = messageContext.getSubcontext(SOAP11Context.class);
      if (soap11Context == null) {
        throw new MessageHandlerException("SOAP 1.1 context was not present in message context");
      }

      log.debug("Unmarshalling SOAP message");
      soapMessage = soap11Context.getEnvelope();
      if (soapMessage == null) {
        throw new MessageHandlerException("SOAP 1.1 envelope was not present in SOAP context");
      }

      soapBodyChildren = soapMessage.getBody().getUnknownXMLObjects();
      thisChild = 0;
    }
  }
}
