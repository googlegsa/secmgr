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
import com.google.common.collect.ImmutableList;
import com.google.enterprise.secmgr.ntlmssp.NtlmMessageDecoder.PayloadHeader;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * An abstraction of the NTLM Challenge (type 2) message.
 *
 * See http://msdn.microsoft.com/en-us/library/cc236621 for details.
 */
@Immutable
public final class NtlmChallenge extends NtlmBase {
  @Nullable private final String targetName;
  @Nonnull private final EnumSet<NtlmSspFlag> flags;
  @Nonnull private final byte[] serverChallenge;
  @Nullable private final List<AvPair> targetInfo;
  @Nullable private final NtlmSspVersion versionInfo;

  /**
   * Make a Challenge message.
   *
   * @param targetName The name of the server or its domain; may be null or empty.
   * @param flags The negotiation flags for the message; never null.
   * @param serverChallenge An 8-byte nonce.
   * @param targetInfo For NTLMv2, some additional info about the server; for NTLMv1 pass null.
   * @param versionInfo The client's version info; may be null.
   * @return A suitable Challenge message.
   */
  public static NtlmChallenge make(@Nullable String targetName, @Nonnull EnumSet<NtlmSspFlag> flags,
      @Nonnull byte[] serverChallenge, @Nullable List<AvPair> targetInfo,
      @Nullable NtlmSspVersion versionInfo) {
    Preconditions.checkNotNull(flags);
    flags = flags.clone();
    checkFlaggedArgument(flags, NtlmSspFlag.REQUEST_TARGET, targetName);
    Preconditions.checkNotNull(serverChallenge);
    Preconditions.checkArgument(serverChallenge.length == 8);
    checkFlaggedArgument(flags, NtlmSspFlag.NEGOTIATE_TARGET_INFO, targetInfo);
    checkFlaggedArgument(flags, NtlmSspFlag.NEGOTIATE_VERSION, versionInfo);
    return new NtlmChallenge(targetName, flags, serverChallenge, targetInfo, versionInfo);
  }

  private NtlmChallenge(String targetName, EnumSet<NtlmSspFlag> flags, byte[] serverChallenge,
      List<AvPair> targetInfo, NtlmSspVersion versionInfo) {
    this.targetName = targetName;
    this.flags = flags;
    this.serverChallenge = serverChallenge;
    this.targetInfo = (targetInfo != null) ? ImmutableList.copyOf(targetInfo) : null;
    this.versionInfo = versionInfo;
  }

  /**
   * @return This message's target name.
   */
  public String getTargetName() {
    return targetName;
  }

  /**
   * @return This message's negotiation flags.
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
   * @return This message's challenge.
   */
  public byte[] getServerChallenge() {
    return copyBytes(serverChallenge);
  }

  /**
   * @return This message's target info.
   */
  public List<AvPair> getTargetInfo() {
    return targetInfo;
  }

  /**
   * @return This message's version info.
   */
  public NtlmSspVersion getVersionInfo() {
    return versionInfo;
  }

  /**
   * Decode a Challenge message.
   *
   * @param message The encoded message.
   * @return The corresponding Challenge message object.
   * @throws UnsupportedEncodingException if there's any kind of decoding error.
   */
  public static NtlmChallenge decode(@Nonnull byte[] message)
      throws UnsupportedEncodingException {
    Preconditions.checkNotNull(message);
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(message);
    checkSignature(decoder);
    checkMessageType(decoder, NtlmMessageType.CHALLENGE);
    PayloadHeader targetHeader = decoder.readPayloadHeader();
    EnumSet<NtlmSspFlag> flags = decodeFlags(decoder);
    byte[] serverChallenge = decoder.readBytes(8);
    String targetName = flags.contains(NtlmSspFlag.REQUEST_TARGET)
        ? decodeString(decoder.readPayload(targetHeader), flags)
        : null;
    if (decoder.atEnd()) {
      return NtlmChallenge.make(targetName, flags, serverChallenge, null, null);
    }
    decoder.skip(8);
    PayloadHeader targetInfoHeader = decoder.readPayloadHeader();
    List<AvPair> targetInfo = flags.contains(NtlmSspFlag.NEGOTIATE_TARGET_INFO)
        ? AvPair.decode(decoder.readPayload(targetInfoHeader))
        : null;
    NtlmSspVersion versionInfo = flags.contains(NtlmSspFlag.NEGOTIATE_VERSION)
        ? NtlmSspVersion.decode(decoder)
        : null;
    return NtlmChallenge.make(targetName, flags, serverChallenge, targetInfo, versionInfo);
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
    encodeMessageType(NtlmMessageType.CHALLENGE, encoder);
    encoder.writePayload(flags.contains(NtlmSspFlag.REQUEST_TARGET)
        ? encodeString(targetName, flags)
        : null);
    encodeFlags(flags, encoder);
    encoder.writeBytes(serverChallenge);
    encoder.writeBytes(RESERVED_8_BYTES);
    encoder.writePayload(flags.contains(NtlmSspFlag.NEGOTIATE_TARGET_INFO)
        ? AvPair.encode(targetInfo)
        : null);
    if (flags.contains(NtlmSspFlag.NEGOTIATE_VERSION)) {
      versionInfo.encode(encoder);
    }
    return encoder.getBytes();
  }

  @Override
  public boolean equals(Object object) {
    if (object == this) { return true; }
    if (!(object instanceof NtlmChallenge)) { return false; }
    NtlmChallenge other = (NtlmChallenge) object;
    return Objects.equals(getTargetName(), other.getTargetName())
        && Objects.equals(getFlags(), other.getFlags())
        && Arrays.equals(getServerChallenge(), other.getServerChallenge())
        && Objects.equals(getTargetInfo(), other.getTargetInfo())
        && Objects.equals(getVersionInfo(), other.getVersionInfo());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getTargetName(), getFlags(), Arrays.hashCode(getServerChallenge()),
        getTargetInfo(), getVersionInfo());
  }
}
