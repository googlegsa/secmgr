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
import com.google.common.base.Function;
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
 * A simple NTLMv1 server.  Knows only how to do the basics.
 */
@NotThreadSafe
public final class NtlmV1Server extends NtlmBase {

  private static final EnumSet<NtlmSspFlag> UNHANDLED_FLAGS =
      EnumSet.of(
          NtlmSspFlag.NEGOTIATE_56,
          NtlmSspFlag.NEGOTIATE_KEY_EXCH,
          NtlmSspFlag.NEGOTIATE_128,
          NtlmSspFlag.NEGOTIATE_VERSION,
          NtlmSspFlag.NEGOTIATE_TARGET_INFO,
          NtlmSspFlag.REQUEST_NON_NT_SESSION_KEY,
          NtlmSspFlag.NEGOTIATE_IDENTIFY,
          NtlmSspFlag.TARGET_TYPE_SERVER,
          NtlmSspFlag.TARGET_TYPE_DOMAIN,
          NtlmSspFlag.ANONYMOUS,
          NtlmSspFlag.NEGOTIATE_NT_ONLY,
          NtlmSspFlag.NEGOTIATE_LM_KEY,
          NtlmSspFlag.NEGOTIATE_DATAGRAM,
          NtlmSspFlag.NEGOTIATE_SEAL,
          NtlmSspFlag.NEGOTIATE_SIGN);

  private static final EnumSet<NtlmSspFlag> NEGOTIABLE_FLAGS =
      EnumSet.of(
          NtlmSspFlag.NEGOTIATE_ALWAYS_SIGN,
          NtlmSspFlag.NEGOTIATE_EXTENDED_SESSION_SECURITY,
          NtlmSspFlag.REQUEST_TARGET);

  @Nullable private final String domainName;
  @Nullable private final String workstationName;
  @Nonnull private final Function<NtlmAuthenticate, String> lookupPassword;
  @Nonnull private final NtlmNegotiate negotiate;
  @Nullable private NtlmChallenge challenge;
  @Nullable private NtlmAuthenticate authenticate;
  @Nullable private byte[] serverChallenge;

  /**
   * Create a new NTLMv1 server builder.
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * A builder class for NTLMv1 servers.
   */
  public static final class Builder {
    private String domainName;
    private String workstationName;
    private Function<NtlmAuthenticate, String> lookupPassword;
    private NtlmNegotiate negotiate;
    private byte[] serverChallenge;

    /**
     * Set the server's ActiveDirectory domain name.
     *
     * @param domainName The domain name.
     * @return The builder object, for convenience.
     */
    public Builder setDomainName(String domainName) {
      this.domainName = domainName;
      return this;
    }

    /**
     * Set the server's workstation name.
     *
     * @param workstationName The workstation name.
     * @return The builder object, for convenience.
     */
    public Builder setWorkstationName(String workstationName) {
      this.workstationName = workstationName;
      return this;
    }

    /**
     * Set the server's password-lookup function.
     *
     * @param lookupPassword The password-lookup function.
     * @return The builder object, for convenience.
     */
    public Builder setLookupPassword(Function<NtlmAuthenticate, String> lookupPassword) {
      this.lookupPassword = lookupPassword;
      return this;
    }

    /**
     * Set the server's copy of the initial negotiate message.
     *
     * @param negotiate The initial negotiate message.
     * @return The builder object, for convenience.
     */
    public Builder setNegotiateMessage(NtlmNegotiate negotiate) {
      this.negotiate = negotiate;
      return this;
    }

    /**
     * Allow unit tests to provide a fixed server challenge.
     */
    @VisibleForTesting
    public Builder setServerChallenge(byte[] serverChallenge) {
      Preconditions.checkNotNull(serverChallenge);
      Preconditions.checkArgument(serverChallenge.length == 8);
      this.serverChallenge = serverChallenge;
      return this;
    }

    /**
     * @return A new NTLMv1 server using the accumulated parameters.
     */
    public NtlmV1Server build() {
      Preconditions.checkArgument(
          !Strings.isNullOrEmpty(domainName)
          || !Strings.isNullOrEmpty(workstationName));
      Preconditions.checkNotNull(lookupPassword);
      Preconditions.checkNotNull(negotiate);
      if (!negotiate.containsFlag(NtlmSspFlag.NEGOTIATE_NTLM)) {
        throw new IllegalArgumentException("Server supports only NTLMv1");
      }
      boolean useUnicode;
      if (!(negotiate.containsFlag(NtlmSspFlag.NEGOTIATE_UNICODE)
              || negotiate.containsFlag(NtlmSspFlag.NEGOTIATE_OEM))) {
        throw new IllegalArgumentException("Must provide UNICODE or OEM flag");
      }
      checkUnhandledFlags(negotiate.getFlags());
      return new NtlmV1Server(domainName, workstationName, lookupPassword, negotiate,
          serverChallenge);
    }
  }

  private NtlmV1Server(String domainName, String workstationName,
      Function<NtlmAuthenticate, String> lookupPassword, NtlmNegotiate negotiate,
      byte[] serverChallenge) {
    this.domainName = domainName;
    this.workstationName = workstationName;
    this.lookupPassword = lookupPassword;
    this.negotiate = negotiate;
    this.serverChallenge = serverChallenge;
    challenge = null;
    authenticate = null;
  }

  /**
   * @return The Negotiate message that was received.
   */
  public NtlmNegotiate getNegotiateMessage() {
    return negotiate;
  }

  /**
   * @return The Challenge message if it has been sent; null otherwise.
   */
  public NtlmChallenge getChallengeMessage() {
    return challenge;
  }

  /**
   * @return The Authenticate message if it has been received; null otherwise.
   */
  public NtlmAuthenticate getAuthenticateMessage() {
    return authenticate;
  }

  /**
   * @return A new Challenge (type 2) message.
   * @throws IllegalStateException if this method was already called.
   */
  public NtlmChallenge createChallengeMessage() {
    Preconditions.checkState(challenge == null);
    EnumSet<NtlmSspFlag> flags
        = EnumSet.of(
            NtlmSspFlag.NEGOTIATE_NTLM,
            getCharsetFlag());
    for (NtlmSspFlag flag : NEGOTIABLE_FLAGS) {
      if (negotiate.containsFlag(flag)) {
        flags.add(flag);
      }
    }
    String targetName = null;
    if (negotiate.containsFlag(NtlmSspFlag.REQUEST_TARGET)) {
      if (!Strings.isNullOrEmpty(domainName)) {
        targetName = domainName;
        flags.add(NtlmSspFlag.TARGET_TYPE_DOMAIN);
      } else {
        targetName = workstationName;
        flags.add(NtlmSspFlag.TARGET_TYPE_SERVER);
      }
    }
    challenge = NtlmChallenge.make(targetName, flags,
        (serverChallenge != null) ? serverChallenge : NtlmCrypto.generateNonce(8),
        null, null);
    return challenge;
  }

  /**
   * Record the Authenticate (type 3) message received from the client.
   *
   * @param authenticate The received message.
   * @throws IllegalStateException if this method was already called.
   */
  public void setAuthenticateMessage(@Nonnull NtlmAuthenticate authenticate) {
    Preconditions.checkNotNull(authenticate);
    Preconditions.checkState(this.authenticate == null);
    this.authenticate = authenticate;
    if (!challenge.containsFlag(getCharsetFlag())) {
      throw new IllegalArgumentException("Message missing encoding flag");
    }
    checkUnhandledFlags(authenticate.getFlags());
  }

  /**
   * @return True only if the client is properly authenticated.
   */
  public boolean isClientAuthenticated()
      throws GeneralSecurityException, UnsupportedEncodingException {
    Preconditions.checkState(this.authenticate != null);
    String password = lookupPassword.apply(authenticate);
    if (password == null) {
      return false;
    }
    byte[] serverChallenge = challenge.getServerChallenge();
    if (authenticate.containsFlag(NtlmSspFlag.NEGOTIATE_EXTENDED_SESSION_SECURITY)) {
      byte[] clientChallenge = Arrays.copyOf(authenticate.getLmChallengeResponse(), 8);
      byte[] ntChallengeResponse
          = NtlmCrypto.generateNtV2ChallengeResponse(serverChallenge, clientChallenge, password);
      return Arrays.equals(ntChallengeResponse, authenticate.getNtChallengeResponse());
    } else {
      byte[] expectedNtChallengeResponse
          = NtlmCrypto.generateNtChallengeResponse(serverChallenge, password);
      if (!Arrays.equals(expectedNtChallengeResponse, authenticate.getNtChallengeResponse())) {
        return false;
      }
      // This is the normal (NoLMResponseNTLMv1 == true) setting:
      if (Arrays.equals(expectedNtChallengeResponse, authenticate.getLmChallengeResponse())) {
        return true;
      }
      // This is the weaker (NoLMResponseNTLMv1 == false) setting:
      byte[] expectedLmChallengeResponse
          = NtlmCrypto.generateLmChallengeResponse(serverChallenge, password);
      return Arrays.equals(expectedLmChallengeResponse, authenticate.getLmChallengeResponse());
    }
  }

  private NtlmSspFlag getCharsetFlag() {
    return negotiate.containsFlag(NtlmSspFlag.NEGOTIATE_UNICODE)
        ? NtlmSspFlag.NEGOTIATE_UNICODE
        : NtlmSspFlag.NEGOTIATE_OEM;
  }

  private static void checkUnhandledFlags(EnumSet<NtlmSspFlag> flags) {
    for (NtlmSspFlag flag : UNHANDLED_FLAGS) {
      if (flags.contains(flag)) {
        throw new IllegalArgumentException("Unsupported flag: " + flag);
      }
    }
  }
}
