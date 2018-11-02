// Copyright 2010 Google Inc.
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

package com.google.enterprise.secmgr.mock;

import com.google.enterprise.secmgr.common.Decorator;
import com.google.enterprise.secmgr.common.SessionUtil;
import com.google.enterprise.secmgr.modules.AuthzResult;
import com.google.enterprise.secmgr.modules.SamlAuthzClient;
import com.google.enterprise.secmgr.saml.Group;
import com.google.enterprise.secmgr.saml.Metadata;
import com.google.enterprise.secmgr.saml.OpenSamlUtil;
import com.google.enterprise.secmgr.saml.SamlSharedData;
import com.google.enterprise.secmgr.saml.SecmgrCredential;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.opensaml.messaging.handler.MessageHandlerException;

/**
 * A mock of a SAML "relying party" client.
 */
public final class MockRelyingParty {
  private static final Logger logger = Logger.getLogger(MockRelyingParty.class.getName());

  private final Metadata metadata;
  private final String peerEntityId;
  private final SamlAuthzClient.Protocol protocol;
  private final boolean useFastAuthz;
  private final SamlSharedData sharedData;

  public MockRelyingParty(Metadata metadata, String localEntityId, String peerEntityId,
      SamlAuthzClient.Protocol protocol, boolean useFastAuthz) {
    this.metadata = metadata;
    this.peerEntityId = peerEntityId;
    this.protocol = protocol;
    this.useFastAuthz = useFastAuthz;
    sharedData = SamlSharedData.make(localEntityId, SamlSharedData.Role.AUTHZ_CLIENT, null);
  }

  public MockRelyingParty(Metadata metadata, String localEntityId, String peerEntityId,
      SamlAuthzClient.Protocol protocol) {
    this(metadata, localEntityId, peerEntityId, protocol, false);
  }

  public AuthzResult authorize(Collection<String> urls, String username)
      throws IOException {
    SamlAuthzClient samlClient = SamlAuthzClient.make(metadata, peerEntityId, sharedData);
    Decorator decorator = SessionUtil.getLogDecorator();
    try {
      SecmgrCredential cred = OpenSamlUtil.makeSecmgrCredential(username, "", "", "",
          Collections.<Group>emptyList());
      return samlClient.sendAuthzRequest(protocol, urls, cred, useFastAuthz, decorator, -1);
    } catch (MessageHandlerException e) {
      logger.log(Level.WARNING, decorator.apply("Authorization response failed: "), e);
      return AuthzResult.makeIndeterminate(urls);
    }
  }
}
