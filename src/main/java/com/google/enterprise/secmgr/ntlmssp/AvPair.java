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
import com.google.common.collect.Lists;

import java.io.UnsupportedEncodingException;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.Immutable;

/**
 * An abstraction for NTLM AvPair structures.  These structures are used in
 * NTLMv2 to transmit various kinds of structured data between the server and
 * client.
 *
 * See http://msdn.microsoft.com/en-us/library/cc236621 for details.
 */
@Immutable
public final class AvPair extends NtlmBase {

  /**
   * This is the "type" of an AvPair.  It determines how the remainder of the
   * AvPair is interpreted.
   */
  public enum MsvAv {
    EOL,
    NETBIOS_COMPUTER_NAME,
    NETBIOS_DOMAIN_NAME,
    DNS_COMPUTER_NAME,
    DNS_DOMAIN_NAME,
    DNS_TREE_NAME,
    FLAGS,
    TIMESTAMP,
    RESTRICTIONS,
    TARGET_NAME,
    CHANNEL_BINDINGS;

    /**
     * @return True only if this type has no value.
     */
    public boolean hasNoValue() {
      return this == MsvAv.EOL;
    }

    /**
     * @return True only if this type has a string value.
     */
    public boolean hasStringValue() {
      return this == MsvAv.NETBIOS_COMPUTER_NAME
          || this == MsvAv.NETBIOS_DOMAIN_NAME
          || this == MsvAv.DNS_COMPUTER_NAME
          || this == MsvAv.DNS_DOMAIN_NAME
          || this == MsvAv.DNS_TREE_NAME
          || this == MsvAv.TARGET_NAME;
    }

    /**
     * @return True only if this type has an integer value.
     */
    public boolean hasIntValue() {
      return this == MsvAv.FLAGS;
    }

    /**
     * @return True only if this type has a bytes value.
     */
    public boolean hasBytesValue() {
      return this == MsvAv.TIMESTAMP
          || this == MsvAv.RESTRICTIONS
          || this == MsvAv.CHANNEL_BINDINGS;
    }

    public static MsvAv decode(int raw)
        throws UnsupportedEncodingException {
      for (MsvAv av : MsvAv.values()) {
        if (av.ordinal() == raw) {
          return av;
        }
      }
      throw new UnsupportedEncodingException("Unknown AvId ordinal: " + raw);
    }
  }

  @Nonnull private final MsvAv type;
  @Nullable private final String stringValue;
  private final int intValue;
  @Nullable private final byte[] bytesValue;

  private AvPair(MsvAv type, String stringValue, int intValue, byte[] bytesValue) {
    this.type = type;
    this.stringValue = stringValue;
    this.intValue = intValue;
    this.bytesValue = bytesValue;
  }

  /**
   * @return The type of this AvPair.
   */
  public MsvAv getType() {
    return type;
  }

  /**
   * Make an AvPair without a value.
   *
   * @param type The type of the pair to make.
   * @return A pair of that type with no value.
   * @throws IllegalArgumentException if the type requires a value.
   */
  public static AvPair makeNoValue(@Nonnull MsvAv type) {
    Preconditions.checkNotNull(type);
    Preconditions.checkArgument(type.hasNoValue());
    return new AvPair(type, null, 0, null);
  }

  /**
   * @return True only if this is an AvPair without a value.
   */
  public boolean hasNoValue() {
    return type.hasNoValue();
  }

  /**
   * Make an AvPair with a string value.
   *
   * @param type The type of the pair to make.
   * @param stringValue The value for the pair to have.
   * @return A pair of that type with the given value.
   * @throws IllegalArgumentException if the type doesn't have a string value.
   */
  public static AvPair makeString(@Nonnull MsvAv type, @Nonnull String stringValue) {
    Preconditions.checkNotNull(type);
    Preconditions.checkArgument(type.hasStringValue());
    Preconditions.checkNotNull(stringValue);
    return new AvPair(type, stringValue, 0, null);
  }

  /**
   * @return True only if this is an AvPair with a string value.
   */
  public boolean hasStringValue() {
    return type.hasStringValue();
  }

  /**
   * @return The string value of this AvPair.
   * @throws IllegalArgumentException if the pair doesn't have a string value.
   */
  public String getStringValue() {
    Preconditions.checkState(hasStringValue());
    return stringValue;
  }

  /**
   * Make an AvPair with an integer value.
   *
   * @param type The type of the pair to make.
   * @param intValue The value for the pair to have.
   * @return A pair of that type with the given value.
   * @throws IllegalArgumentException if the type doesn't have an integer value.
   */
  public static AvPair makeInt(@Nonnull MsvAv type, int intValue) {
    Preconditions.checkNotNull(type);
    Preconditions.checkArgument(type.hasIntValue());
    return new AvPair(type, null, intValue, null);
  }

  /**
   * @return True only if this is an AvPair with an integer value.
   */
  public boolean hasIntValue() {
    return type.hasIntValue();
  }

  /**
   * @return The integer value of this AvPair.
   * @throws IllegalArgumentException if the pair doesn't have an integer value.
   */
  public int getIntValue() {
    Preconditions.checkState(hasIntValue());
    return intValue;
  }

  /**
   * Make an AvPair with a bytes value.
   *
   * @param type The type of the pair to make.
   * @param bytesValue The value for the pair to have.
   * @return A pair of that type with the given value.
   * @throws IllegalArgumentException if the type doesn't have a bytes value.
   */
  public static AvPair makeBytes(@Nonnull MsvAv type, @Nonnull byte[] bytesValue) {
    Preconditions.checkNotNull(type);
    Preconditions.checkArgument(type.hasBytesValue());
    Preconditions.checkNotNull(bytesValue);
    return new AvPair(type, null, 0, bytesValue);
  }

  /**
   * @return True only if this is an AvPair with a bytes value.
   */
  public boolean hasBytesValue() {
    return type.hasBytesValue();
  }

  /**
   * @return The bytes value of this AvPair.
   * @throws IllegalArgumentException if the pair doesn't have a bytes value.
   */
  public byte[] getBytesValue() {
    Preconditions.checkState(hasBytesValue());
    return bytesValue;
  }

  /**
   * Make a "flags" AvPair.
   *
   * @param flags The flags that the pair will have.
   * @return A "flags" pair.
   */
  public static AvPair makeFlags(int flags) {
    return makeInt(MsvAv.FLAGS, flags);
  }

  /**
   * Make an EOL AvPair.
   *
   * @return An EOL AvPair.
   */
  public static AvPair makeEol() {
    return makeNoValue(MsvAv.EOL);
  }

  /**
   * @return True only if this is an EOL AvPair.
   */
  public boolean isEol() {
    return type == MsvAv.EOL;
  }

  // The encoded form of an AvPair is:
  // AvId (16 bytes)
  // AvLen (16 bytes)
  // Value (AvLen bytes)

  static List<AvPair> decode(@Nonnull byte[] payload)
      throws UnsupportedEncodingException {
    Preconditions.checkNotNull(payload);
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(payload);
    List<AvPair> pairs = Lists.newArrayList();
    while (true) {
      AvPair pair = AvPair.decode(decoder);
      if (pair.isEol()) {
        if (!decoder.atEnd()) {
          throw new UnsupportedEncodingException("EOL not at end of block: " + decoder.getIndex());
        }
        break;
      }
      pairs.add(pair);
    }
    return pairs;
  }

  private static AvPair decode(@Nonnull NtlmMessageDecoder decoder)
      throws UnsupportedEncodingException {
    MsvAv type = MsvAv.decode(decoder.read16());
    int avLen = decoder.read16();
    if (type.hasNoValue()) {
      return makeNoValue(type);
    }
    if (type.hasIntValue()) {
      if (avLen != 4) {
        throw new UnsupportedEncodingException("Length must be 4: " + avLen);
      }
      return makeInt(type, decoder.read32());
    }
    if (type.hasStringValue()) {
      return makeString(type, decodeString(decoder.readBytes(avLen), UNICODE_CHARSET));
    }
    if (type.hasBytesValue()) {
      return makeBytes(type, decoder.readBytes(avLen));
    }
    throw new UnsupportedEncodingException("Unknown type: " + type);
  }

  static byte[] encode(@Nonnull List<AvPair> pairs)
      throws UnsupportedEncodingException {
    Preconditions.checkNotNull(pairs);
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    for (AvPair pair : pairs) {
      pair.encode(encoder);
    }
    AvPair.makeEol().encode(encoder);
    return encoder.getBytes();
  }

  private void encode(@Nonnull NtlmMessageEncoder encoder)
      throws UnsupportedEncodingException {
    encoder.write16(type.ordinal());         // AvId
    if (isEol()) {
      encoder.write16(0);                    // AvLen
    } else if (hasIntValue()) {
      encoder.write16(4);                    // AvLen
      encoder.write32(intValue);             // Value
    } else if (hasStringValue()) {
      byte[] encoded = stringValue.getBytes(UNICODE_CHARSET);
      encoder.write16(encoded.length);       // AvLen
      encoder.writeBytes(encoded);           // Value
    } else if (hasBytesValue()) {
      encoder.write16(bytesValue.length);  // AvLen
      encoder.writeBytes(bytesValue);      // Value
    } else {
      throw new IllegalStateException("Unknown type: " + type);
    }
  }
}
