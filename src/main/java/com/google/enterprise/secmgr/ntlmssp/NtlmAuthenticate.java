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

import com.google.common.base.Preconditions;
import com.google.common.base.Strings;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * An abstraction of the NTLM Authenticate (type 3) message.
 *
 * See http://msdn.microsoft.com/en-us/library/cc236621 for details.
 */
public final class NtlmAuthenticate extends NtlmBase {
  @Nonnull private final byte[] lmChallengeResponse;
  @Nonnull private final byte[] ntChallengeResponse;
  @Nonnull private final String domainName;
  @Nonnull private final String userName;
  @Nonnull private final String workstationName;
  @Nullable private final byte[] encryptedRandomSessionKey;
  @Nonnull private final EnumSet<NtlmSspFlag> flags;
  @Nullable private final NtlmSspVersion versionInfo;
  @Nullable private final byte[] mic;

  /**
   * Make a Authenticate message.
   *
   * @param lmChallengeResponse The LM challenge response.
   * @param ntChallengeResponse The NT challenge response.
   * @param domainName The client's Active Directory domain.
   * @param userName The client's user name.
   * @param workstationName The client's workstation name null.
   * @param encryptedRandomSessionKey The session key.
   * @param flags The negotiation flags for the message.
   * @param versionInfo The client's version info.
   * @param mic For NTLMv2, a 16-byte message integrity check; for NTLMv1 pass null.
   * @return A suitable Authenticate message.
   * @throws IllegalArgumentException if neither domainName or workstationName is non-null.
   */
  public static NtlmAuthenticate make(@Nonnull byte[] lmChallengeResponse,
      @Nonnull byte[] ntChallengeResponse, @Nullable String domainName, @Nullable String userName,
      @Nullable String workstationName, @Nullable byte[] encryptedRandomSessionKey,
      @Nonnull EnumSet<NtlmSspFlag> flags, @Nullable NtlmSspVersion versionInfo,
      @Nullable byte[] mic) {
    Preconditions.checkNotNull(flags);
    flags = flags.clone();
    Preconditions.checkNotNull(lmChallengeResponse);
    Preconditions.checkNotNull(ntChallengeResponse);
    Preconditions.checkArgument(
        !Strings.isNullOrEmpty(domainName)
        || !Strings.isNullOrEmpty(workstationName));
    checkFlaggedArgument(flags, NtlmSspFlag.NEGOTIATE_KEY_EXCH, encryptedRandomSessionKey);
    checkFlaggedArgument(flags, NtlmSspFlag.NEGOTIATE_VERSION, versionInfo);
    if (mic != null) {
      Preconditions.checkArgument(mic.length == 16);
    }
    return new NtlmAuthenticate(lmChallengeResponse, ntChallengeResponse, domainName, userName,
        workstationName, encryptedRandomSessionKey, flags, versionInfo, mic);
  }

  private NtlmAuthenticate(byte[] lmChallengeResponse, byte[] ntChallengeResponse,
      String domainName, String userName, String workstationName, byte[] encryptedRandomSessionKey,
      EnumSet<NtlmSspFlag> flags, NtlmSspVersion versionInfo, byte[] mic) {
    this.lmChallengeResponse = lmChallengeResponse;
    this.ntChallengeResponse = ntChallengeResponse;
    this.domainName = domainName;
    this.userName = userName;
    this.workstationName = workstationName;
    this.encryptedRandomSessionKey = encryptedRandomSessionKey;
    this.flags = flags;
    this.versionInfo = versionInfo;
    this.mic = mic;
  }

  /**
   * @return This message's LM challenge response.
   */
  public byte[] getLmChallengeResponse() {
    return copyBytes(lmChallengeResponse);
  }

  /**
   * @return This message's NT challenge response.
   */
  public byte[] getNtChallengeResponse() {
    return copyBytes(ntChallengeResponse);
  }

  /**
   * @return This message's Active Directory domain.
   */
  public String getDomainName() {
    return domainName;
  }

  /**
   * @return This message's user name.
   */
  public String getUserName() {
    return userName;
  }

  /**
   * @return This message's workstation name.
   */
  public String getWorkstationName() {
    return workstationName;
  }

  /**
   * @return This message's session key.
   */
  public byte[] getEncryptedRandomSessionKey() {
    return copyBytes(encryptedRandomSessionKey);
  }

  /**
   * @return This message's flags.
   */
  public EnumSet<NtlmSspFlag> getFlags() {
    return flags.clone();
  }

  /**
   * Test for a particular flag.
   *
   * @param flag The flag to test for.
   * @return True only if the given flag is in the message's flag set.
   */
  public boolean containsFlag(NtlmSspFlag flag) {
    return flags.contains(flag);
  }

  /**
   * @return This message's version info.
   */
  public NtlmSspVersion getVersionInfo() {
    return versionInfo;
  }

  /**
   * @return This message's MIC.
   */
  public byte[] getMic() {
    return copyBytes(mic);
  }

  /**
   * Decode a Authenticate message.
   *
   * @param message The raw message to decode.
   * @return The corresponding Authenticate message object.
   * @throws UnsupportedEncodingException if there's any kind of decoding error.
   */
  public static NtlmAuthenticate decode(@Nonnull byte[] message, boolean hasMic)
      throws UnsupportedEncodingException {
    Preconditions.checkNotNull(message);
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(message);
    checkSignature(decoder);
    checkMessageType(decoder, NtlmMessageType.AUTHENTICATE);
    byte[] lmChallengeResponse = decoder.readPayload();
    byte[] ntChallengeResponse = decoder.readPayload();
    byte[] rawDomainName = decoder.readPayload();
    byte[] rawUserName = decoder.readPayload();
    byte[] rawWorkstationName = decoder.readPayload();
    byte[] encryptedRandomSessionKey = decoder.readPayload();
    EnumSet<NtlmSspFlag> flags = decodeFlags(decoder);
    String domainName = decodeString(rawDomainName, flags);
    String userName = decodeString(rawUserName, flags);
    String workstationName = decodeString(rawWorkstationName, flags);
    if (!flags.contains(NtlmSspFlag.NEGOTIATE_KEY_EXCH)) {
      encryptedRandomSessionKey = null;
    }
    NtlmSspVersion versionInfo = flags.contains(NtlmSspFlag.NEGOTIATE_VERSION)
        ? NtlmSspVersion.decode(decoder)
        : null;
    byte[] mic = hasMic ? decoder.readBytes(16) : null;
    return NtlmAuthenticate.make(lmChallengeResponse, ntChallengeResponse, domainName, userName,
        workstationName, encryptedRandomSessionKey, flags, versionInfo, mic);
  }

  /**
   * Encode this message.
   *
   * @return The encoded message.
   * @throws UnsupportedEncodingException if there's any kind of encoding error.
   */
  public byte[] encode()
      throws UnsupportedEncodingException {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    encodeSignature(encoder);
    encodeMessageType(NtlmMessageType.AUTHENTICATE, encoder);
    encoder.writePayload(lmChallengeResponse);
    encoder.writePayload(ntChallengeResponse);
    encoder.writePayload(encodeString(domainName, flags));
    encoder.writePayload(encodeString(userName, flags));
    encoder.writePayload(encodeString(workstationName, flags));
    encoder.writePayload(encryptedRandomSessionKey);
    encodeFlags(flags, encoder);
    if (flags.contains(NtlmSspFlag.NEGOTIATE_VERSION)) {
      versionInfo.encode(encoder);
    }
    if (mic != null) {
      encoder.writeBytes(mic);
    }
    return encoder.getBytes();
  }

  @Override
  public boolean equals(Object object) {
    if (object == this) { return true; }
    if (!(object instanceof NtlmAuthenticate)) { return false; }
    NtlmAuthenticate other = (NtlmAuthenticate) object;
    return Arrays.equals(getLmChallengeResponse(), other.getLmChallengeResponse())
        && Arrays.equals(getNtChallengeResponse(), other.getNtChallengeResponse())
        && Objects.equals(getDomainName(), other.getDomainName())
        && Objects.equals(getUserName(), other.getUserName())
        && Objects.equals(getWorkstationName(), other.getWorkstationName())
        && Arrays.equals(getEncryptedRandomSessionKey(), other.getEncryptedRandomSessionKey())
        && Objects.equals(getFlags(), other.getFlags())
        && Objects.equals(getVersionInfo(), other.getVersionInfo())
        && Arrays.equals(getMic(), other.getMic());
  }

  @Override
  public int hashCode() {
    return Objects.hash(Arrays.hashCode(getLmChallengeResponse()),
        Arrays.hashCode(getNtChallengeResponse()), getDomainName(), getUserName(),
        getWorkstationName(), Arrays.hashCode(getEncryptedRandomSessionKey()), getFlags(),
        getVersionInfo(), Arrays.hashCode(getMic()));
  }
}
