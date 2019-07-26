package com.google.enterprise.secmgr.saml;

import org.opensaml.messaging.context.BaseContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerChain;
import org.opensaml.saml.common.SAMLObject;

/**
 * Simple class to store an associated {@link MessageHandler} or {@link MessageHandlerChain} in a
 * {@link MessageContext}
 */
public class InboundMessageHandlerContext extends BaseContext {
  private MessageHandler<SAMLObject> handler;

  public void setMessageHandler(MessageHandler<SAMLObject> handler) {
    this.handler = handler;
  }

  public MessageHandler<SAMLObject> getMessageHandler() {
    return handler;
  }
}
