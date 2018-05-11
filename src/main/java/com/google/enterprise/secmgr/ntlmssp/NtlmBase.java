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
import java.util.Arrays;
import java.util.EnumSet;

import javax.annotation.concurrent.Immutable;

/**
 * A base class for NTLM message processing.  Contains shared constants, as well
 * as a bunch of static helper methods.
 */
@Immutable
abstract class NtlmBase {

  // "NTLMSSP\0" in US-ASCII encoding.
  protected static final byte[] NTLMSSP_SIGNATURE =
      new byte[] { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 };

  protected static final byte[] RESERVED_8_BYTES =
      new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  private static final String CP850_CHARSET = "Cp850";
  private static final String ASCII_CHARSET = "US-ASCII";
  protected static final String UNICODE_CHARSET = "UTF-16LE";

  protected static String oemCharset;
  static {
    try {
      "".getBytes(CP850_CHARSET);
      oemCharset = CP850_CHARSET;
    } catch (UnsupportedEncodingException e) {
      oemCharset = ASCII_CHARSET;
    }
  }

  protected static void checkSignature(NtlmMessageDecoder decoder)
      throws UnsupportedEncodingException {
    if (!Arrays.equals(NTLMSSP_SIGNATURE, decoder.readBytes(8))) {
      throw new UnsupportedEncodingException("Message missing NTLM signature");
    }
  }

  protected static void encodeSignature(NtlmMessageEncoder encoder) {
    encoder.writeBytes(NTLMSSP_SIGNATURE);
  }

  protected static void checkMessageType(NtlmMessageDecoder decoder, NtlmMessageType type)
      throws UnsupportedEncodingException {
    int actual = decoder.read32();
    if (actual != type.getCode()) {
      throw new UnsupportedEncodingException("Incorrect NTLM message type: " + actual
          + " expected: " + type.getCode());
    }
  }

  protected static void encodeMessageType(NtlmMessageType type, NtlmMessageEncoder encoder) {
    encoder.write32(type.getCode());
  }

  protected static EnumSet<NtlmSspFlag> decodeFlags(NtlmMessageDecoder decoder)
      throws UnsupportedEncodingException {
    int flags = decoder.read32();
    EnumSet<NtlmSspFlag> result = EnumSet.noneOf(NtlmSspFlag.class);
    for (NtlmSspFlag flag : NtlmSspFlag.values()) {
      if ((flags & (1 << flag.ordinal())) != 0) {
        result.add(flag);
      }
    }
    return result;
  }

  protected static void encodeFlags(EnumSet<NtlmSspFlag> flags, NtlmMessageEncoder encoder) {
    int result = 0;
    for (NtlmSspFlag flag : flags) {
      result |= (1 << flag.ordinal());
    }
    encoder.write32(result);
  }

  protected static String decodeString(byte[] raw, EnumSet<NtlmSspFlag> flags)
      throws UnsupportedEncodingException {
    if (flags.contains(NtlmSspFlag.NEGOTIATE_UNICODE)) {
      return decodeString(raw, UNICODE_CHARSET);
    }
    if (flags.contains(NtlmSspFlag.NEGOTIATE_OEM)) {
      return decodeString(raw, oemCharset);
    }
    throw new UnsupportedEncodingException(
        "Must specify either NEGOTIATE_UNICODE or NEGOTIATE_OEM");
  }

  protected static String decodeString(byte[] raw, String charset)
      throws UnsupportedEncodingException {
    return (raw != null) ? new String(raw, charset) : null;
  }

  protected static byte[] encodeString(String string, EnumSet<NtlmSspFlag> flags)
      throws UnsupportedEncodingException {
    if (flags.contains(NtlmSspFlag.NEGOTIATE_UNICODE)) {
      return encodeUnicodeString(string);
    }
    if (flags.contains(NtlmSspFlag.NEGOTIATE_OEM)) {
      return encodeOemString(string);
    }
    throw new UnsupportedEncodingException(
        "Must specify either NEGOTIATE_UNICODE or NEGOTIATE_OEM");
  }

  protected static byte[] encodeOemString(String string)
      throws UnsupportedEncodingException {
    return (string != null) ? string.toUpperCase().getBytes(oemCharset) : null;
  }

  protected static byte[] encodeUnicodeString(String string)
      throws UnsupportedEncodingException {
    return (string != null) ? string.getBytes(UNICODE_CHARSET) : null;
  }

  protected static void checkFlaggedArgument(EnumSet<NtlmSspFlag> flags, NtlmSspFlag flag,
      Object argument) {
    if (flags.contains(flag)) {
      Preconditions.checkNotNull(argument);
    } else if (argument != null) {
      flags.add(flag);
    }
  }

  protected static byte[] copyBytes(byte[] bytes) {
    return (bytes != null) ? Arrays.copyOf(bytes, bytes.length) : null;
  }
}
