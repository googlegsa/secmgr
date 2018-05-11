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

import java.io.UnsupportedEncodingException;
import java.util.EnumSet;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * An abstraction of the NTLM Negotiate (type 1) message.
 *
 * See http://msdn.microsoft.com/en-us/library/cc236621 for details.
 */
@Immutable
public final class NtlmNegotiate extends NtlmBase {
  @Nonnull private final EnumSet<NtlmSspFlag> flags;
  @Nullable private final String domainName;
  @Nullable private final String workstationName;
  @Nullable private final NtlmSspVersion versionInfo;

  /**
   * Make a Negotiate message.
   *
   * @param flags The negotiation flags for the message; never null.
   * @param domainName The client's Active Directory domain; may be null or empty.
   * @param workstationName The client's workstation name; may be null or empty.
   * @param versionInfo The client's version info; may be null.
   * @return A suitable Negotiate message.
   */
  public static NtlmNegotiate make(@Nonnull EnumSet<NtlmSspFlag> flags, @Nullable String domainName,
      @Nullable String workstationName, @Nullable NtlmSspVersion versionInfo) {
    Preconditions.checkNotNull(flags);
    flags = flags.clone();
    checkFlaggedArgument(flags, NtlmSspFlag.NEGOTIATE_OEM_DOMAIN_SUPPLIED, domainName);
    checkFlaggedArgument(flags, NtlmSspFlag.NEGOTIATE_OEM_WORKSTATION_SUPPLIED, workstationName);
    checkFlaggedArgument(flags, NtlmSspFlag.NEGOTIATE_VERSION, versionInfo);
    return new NtlmNegotiate(flags, domainName, workstationName, versionInfo);
  }

  private NtlmNegotiate(EnumSet<NtlmSspFlag> flags, String domainName,
      String workstationName, NtlmSspVersion versionInfo) {
    this.flags = flags;
    this.domainName = domainName;
    this.workstationName = workstationName;
    this.versionInfo = versionInfo;
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
   * @return This message's Active Directory domain.
   */
  public String getDomainName() {
    return domainName;
  }

  /**
   * @return This message's workstation name.
   */
  public String getWorkstationName() {
    return workstationName;
  }

  /**
   * @return This message's version info.
   */
  public NtlmSspVersion getVersionInfo() {
    return versionInfo;
  }

  /**
   * Decode a Negotiate message.
   *
   * @param message The raw message to decode.
   * @return The corresponding Negotiate message object.
   * @throws UnsupportedEncodingException if there's any kind of decoding error.
   */
  public static NtlmNegotiate decode(@Nonnull byte[] message)
      throws UnsupportedEncodingException {
    Preconditions.checkNotNull(message);
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(message);
    checkSignature(decoder);
    checkMessageType(decoder, NtlmMessageType.NEGOTIATE);
    EnumSet<NtlmSspFlag> flags = decodeFlags(decoder);
    String domainName;
    if (flags.contains(NtlmSspFlag.NEGOTIATE_OEM_DOMAIN_SUPPLIED)) {
      domainName = decodeString(decoder.readPayload(), oemCharset);
    } else {
      decoder.skipPayloadHeader();
      domainName = null;
    }
    String workstationName;
    if (flags.contains(NtlmSspFlag.NEGOTIATE_OEM_WORKSTATION_SUPPLIED)) {
      workstationName = decodeString(decoder.readPayload(), oemCharset);
    } else {
      decoder.skipPayloadHeader();
      workstationName = null;
    }
    NtlmSspVersion versionInfo = flags.contains(NtlmSspFlag.NEGOTIATE_VERSION)
        ? NtlmSspVersion.decode(decoder)
        : null;
    return NtlmNegotiate.make(flags, domainName, workstationName, versionInfo);
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
    encodeMessageType(NtlmMessageType.NEGOTIATE, encoder);
    encodeFlags(flags, encoder);
    encoder.writePayload(encodeOemString(
        flags.contains(NtlmSspFlag.NEGOTIATE_OEM_DOMAIN_SUPPLIED) ? domainName : ""));
    encoder.writePayload(encodeOemString(
        flags.contains(NtlmSspFlag.NEGOTIATE_OEM_WORKSTATION_SUPPLIED) ? workstationName : ""));
    if (flags.contains(NtlmSspFlag.NEGOTIATE_VERSION)) {
      versionInfo.encode(encoder);
    }
    return encoder.getBytes();
  }

  @Override
  public boolean equals(Object object) {
    if (object == this) { return true; }
    if (!(object instanceof NtlmNegotiate)) { return false; }
    NtlmNegotiate other = (NtlmNegotiate) object;
    return Objects.equals(getFlags(), other.getFlags())
        && Objects.equals(getDomainName(), other.getDomainName())
        && Objects.equals(getWorkstationName(), other.getWorkstationName())
        && Objects.equals(getVersionInfo(), other.getVersionInfo());
  }

  @Override
  public int hashCode() {
    return Objects.hash(getFlags(), getDomainName(), getWorkstationName(), getVersionInfo());
  }
}
