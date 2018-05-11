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

package com.google.enterprise.secmgr.ntlmssp;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.base.Strings;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.EnumSet;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * A simple NTLMv1 client.  Knows only how to do the basics.
 */
@NotThreadSafe
public final class NtlmV1Client extends NtlmBase {

  private static final EnumSet<NtlmSspFlag> DEFAULT_INITIAL_FLAGS =
      EnumSet.of(
          NtlmSspFlag.NEGOTIATE_ALWAYS_SIGN,
          NtlmSspFlag.NEGOTIATE_EXTENDED_SESSION_SECURITY,
          NtlmSspFlag.NEGOTIATE_NTLM,
          NtlmSspFlag.NEGOTIATE_OEM,
          NtlmSspFlag.NEGOTIATE_UNICODE,
          NtlmSspFlag.REQUEST_TARGET);

  @Nullable private final String domainName;
  @Nullable private final String userName;
  @Nonnull private final String password;
  @Nullable private final String workstationName;
  @Nonnull private final EnumSet<NtlmSspFlag> initialFlags;
  private final boolean noLmResponseNtlmV1;
  @Nullable private NtlmNegotiate negotiate;
  @Nullable private NtlmChallenge challenge;
  @Nullable private NtlmAuthenticate authenticate;
  @Nullable private byte[] clientChallenge;

  /**
   * Create a new NTLMv1 client builder.
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * A builder class for NTLMv1 clients.
   */
  public static final class Builder {
    private String domainName;
    private String userName;
    private String password;
    private String workstationName;
    private EnumSet<NtlmSspFlag> initialFlags;
    private boolean noLmResponseNtlmV1;
    private byte[] clientChallenge;

    private Builder() {
      initialFlags = DEFAULT_INITIAL_FLAGS.clone();
      noLmResponseNtlmV1 = true;
    }

    /**
     * Set the client's ActiveDirectory domain name.
     *
     * @param domainName The domain name.
     * @return The builder object, for convenience.
     */
    public Builder setDomainName(String domainName) {
      this.domainName = domainName;
      return this;
    }

    /**
     * Set the client's user name.
     *
     * @param userName The user name.
     * @return The builder object, for convenience.
     */
    public Builder setUserName(String userName) {
      this.userName = userName;
      return this;
    }

    /**
     * Set the client's password.
     *
     * @param password The password.
     * @return The builder object, for convenience.
     */
    public Builder setPassword(@Nonnull String password) {
      Preconditions.checkNotNull(password);
      this.password = password;
      return this;
    }

    /**
     * Set the client's workstation name.
     *
     * @param workstationName The workstation name.
     * @return The builder object, for convenience.
     */
    public Builder setWorkstationName(String workstationName) {
      this.workstationName = workstationName;
      return this;
    }

    /**
     * Set the initial flags to be sent with the Negotiate message.  The default
     * set of initial flags is
     *
     * NEGOTIATE_ALWAYS_SIGN
     * NEGOTIATE_EXTENDED_SESSION_SECURITY
     * NEGOTIATE_NTLM
     * NEGOTIATE_OEM
     * NEGOTIATE_UNICODE
     * REQUEST_TARGET
     *
     * The client manages the following flags, so they shouldn't be set here:
     *
     * NEGOTIATE_OEM_DOMAIN_SUPPLIED
     * NEGOTIATE_OEM_WORKSTATION_SUPPLIED
     *
     * @param initialFlags The initial flags to use.
     * @return The builder object, for convenience.
     */
    public Builder setInitialFlags(@Nonnull EnumSet<NtlmSspFlag> initialFlags) {
      Preconditions.checkNotNull(initialFlags);
      this.initialFlags = initialFlags.clone();
      return this;
    }

    /**
     * Set the NoLMResponseNTLMv1 flag.  This flag is set to true by default,
     * and all modern versions of Windows use that setting.  Setting it to false
     * provides weaker security and is not recommended.
     *
     * @param noLmResponseNtlmV1 The new flag value.
     * @return The builder object, for convenience.
     */
    public Builder setNoLmResponseNtlmV1(boolean noLmResponseNtlmV1) {
      this.noLmResponseNtlmV1 = noLmResponseNtlmV1;
      return this;
    }

    /**
     * Allow unit tests to provide a fixed client challenge.
     */
    @VisibleForTesting
    public Builder setClientChallenge(byte[] clientChallenge) {
      Preconditions.checkNotNull(clientChallenge);
      Preconditions.checkArgument(clientChallenge.length == 8);
      this.clientChallenge = clientChallenge;
      return this;
    }

    /**
     * @return A new NTLMv1 client using the accumulated parameters.
     */
    public NtlmV1Client build() {
      Preconditions.checkNotNull(password);
      return new NtlmV1Client(domainName, userName, password, workstationName,
          initialFlags.clone(), noLmResponseNtlmV1, clientChallenge);
    }
  }

  private NtlmV1Client(String domainName, String userName, String password,
      String workstationName, EnumSet<NtlmSspFlag> initialFlags, boolean noLmResponseNtlmV1,
      byte[] clientChallenge) {
    this.domainName = domainName;
    this.userName = userName;
    this.password = password;
    this.workstationName = workstationName;
    this.initialFlags = initialFlags;
    this.noLmResponseNtlmV1 = noLmResponseNtlmV1;
    this.clientChallenge = clientChallenge;
    negotiate = null;
    challenge = null;
    authenticate = null;
  }

  /**
   * @return The Negotiate message if it has been sent; null otherwise.
   */
  public NtlmNegotiate getNegotiateMessage() {
    return negotiate;
  }

  /**
   * @return The Challenge message if it has been received; null otherwise.
   */
  public NtlmChallenge getChallengeMessage() {
    return challenge;
  }

  /**
   * @return The Authenticate message if it has been sent; null otherwise.
   */
  public NtlmAuthenticate getAuthenticateMessage() {
    return authenticate;
  }

  /**
   * @return A new Negotiate (type 1) message.
   * @throws IllegalStateException if this method was already called.
   */
  public NtlmNegotiate createNegotiateMessage() {
    Preconditions.checkState(negotiate == null);
    EnumSet<NtlmSspFlag> flags = initialFlags.clone();
    flags.add(NtlmSspFlag.NEGOTIATE_NTLM);
    flags.add(NtlmSspFlag.NEGOTIATE_OEM);
    flags.add(NtlmSspFlag.NEGOTIATE_UNICODE);
    flags.add(NtlmSspFlag.REQUEST_TARGET);
    if (!Strings.isNullOrEmpty(domainName)) {
      flags.add(NtlmSspFlag.NEGOTIATE_OEM_DOMAIN_SUPPLIED);
    }
    if (!Strings.isNullOrEmpty(workstationName)) {
      flags.add(NtlmSspFlag.NEGOTIATE_OEM_WORKSTATION_SUPPLIED);
    }
    negotiate = NtlmNegotiate.make(flags, domainName, workstationName, null);
    return negotiate;
  }

  /**
   * Record the server's Challenge (type 2) message.
   *
   * @param challenge The Challenge message received from the server.
   * @throws IllegalArgumentException If the message isn't suitable.
   * @throws IllegalStateException if this method was already called.
   */
  public void setChallengeMessage(@Nonnull NtlmChallenge challenge) {
    Preconditions.checkNotNull(challenge);
    Preconditions.checkState(this.challenge == null);
    this.challenge = challenge;
    if (!challenge.containsFlag(NtlmSspFlag.NEGOTIATE_NTLM)) {
      throw new IllegalArgumentException("Server doesn't support NTLMv1");
    }
    if (!(challenge.containsFlag(NtlmSspFlag.NEGOTIATE_UNICODE)
            || challenge.containsFlag(NtlmSspFlag.NEGOTIATE_OEM))) {
      throw new IllegalArgumentException("Server failed to provide UNICODE or OEM flag");
    }
  }

  /**
   * @return An Authenticate (type 3) message.
   * @throws GeneralSecurityException if there's a crypto library error.
   * @throws UnsupportedEncodingException if there are errors encoding the string arguments.
   * @throws IllegalStateException if this method was already called.
   */
  public NtlmAuthenticate createAuthenticateMessage()
      throws GeneralSecurityException, UnsupportedEncodingException {
    Preconditions.checkNotNull(challenge);
    Preconditions.checkState(authenticate == null);
    EnumSet<NtlmSspFlag> flags
        = EnumSet.of(
            NtlmSspFlag.NEGOTIATE_NTLM,
            getEncodingFlag());
    byte[] serverChallenge = challenge.getServerChallenge();
    byte[] lmChallengeResponse;
    byte[] ntChallengeResponse;
    if (challenge.containsFlag(NtlmSspFlag.NEGOTIATE_EXTENDED_SESSION_SECURITY)) {
      flags.add(NtlmSspFlag.NEGOTIATE_EXTENDED_SESSION_SECURITY);
      byte[] clientChallenge = (this.clientChallenge != null)
          ? this.clientChallenge
          : NtlmCrypto.generateNonce(8);
      lmChallengeResponse = Arrays.copyOf(clientChallenge, 24);
      ntChallengeResponse =
          NtlmCrypto.generateNtV2ChallengeResponse(serverChallenge, clientChallenge, password);
    } else {
      ntChallengeResponse = NtlmCrypto.generateNtChallengeResponse(serverChallenge, password);
      if (noLmResponseNtlmV1) {
        lmChallengeResponse = ntChallengeResponse;
      } else {
        lmChallengeResponse = NtlmCrypto.generateLmChallengeResponse(serverChallenge, password);
      }
    }
    authenticate = NtlmAuthenticate.make(lmChallengeResponse, ntChallengeResponse,
        getDomainName(), userName, getWorkstationName(), null, flags, null, null);
    return authenticate;
  }

  private NtlmSspFlag getEncodingFlag() {
    return challenge.containsFlag(NtlmSspFlag.NEGOTIATE_UNICODE)
        ? NtlmSspFlag.NEGOTIATE_UNICODE
        : NtlmSspFlag.NEGOTIATE_OEM;
  }

  private String getDomainName() {
    return
        (Strings.isNullOrEmpty(domainName)
            && challenge.containsFlag(NtlmSspFlag.TARGET_TYPE_DOMAIN))
        ? challenge.getTargetName()
        : domainName;
  }

  private String getWorkstationName() {
    return challenge.containsFlag(NtlmSspFlag.TARGET_TYPE_SERVER)
        ? challenge.getTargetName()
        : workstationName;
  }
}
