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

import com.google.common.collect.Lists;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.List;

import javax.annotation.concurrent.NotThreadSafe;

/**
 * An abstraction for encoding NTLM messages.  The strategy is to write the
 * header and payload separately, then fixup all the payload offsets in the
 * header when everything is done.
 */
@NotThreadSafe
final class NtlmMessageEncoder {
  private final ByteArrayOutputStream header;
  private final ByteArrayOutputStream payload;
  private final List<Integer> payloadOffsets;

  public static NtlmMessageEncoder make() {
    return new NtlmMessageEncoder();
  }

  private NtlmMessageEncoder() {
    header = new ByteArrayOutputStream();
    payload = new ByteArrayOutputStream();
    payloadOffsets = Lists.newArrayList();
  }

  public void write8(int value)
      throws UnsupportedEncodingException {
    if (!(value >= 0 && value < 0x100)) {
      throw new UnsupportedEncodingException(
          "Value not representable as 8-bit unsigned: " + value);
    }
    header.write((byte) value);
  }

  public void write16(int value)
      throws UnsupportedEncodingException {
    if (!(value >= 0 && value < 0x10000)) {
      throw new UnsupportedEncodingException(
          "Value not representable as 16-bit unsigned: " + value);
    }
    header.write((byte) (value & 0xff));
    header.write((byte) ((value >> 8) & 0xff));
  }

  public void write32(int value) {
    header.write((byte) (value & 0xff));
    header.write((byte) ((value >> 8) & 0xff));
    header.write((byte) ((value >> 16) & 0xff));
    header.write((byte) ((value >> 24) & 0xff));
  }

  public void writeBytes(byte[] bytes) {
    if (bytes != null) {
      header.write(bytes, 0, bytes.length);
    }
  }

  public void writePayload(byte[] bytes)
      throws UnsupportedEncodingException {
    if (bytes == null) {
      bytes = new byte[0];
    }
    write16(bytes.length);  // length of payload
    write16(bytes.length);  // maximum length of payload
    payloadOffsets.add(header.size());
    write32(payload.size());  // offset of payload in result (will be fixed later)
    payload.write(bytes, 0, bytes.length);
  }

  public byte[] getBytes() {
    int payloadStart = header.size();
    byte[] result = new byte[payloadStart + payload.size()];
    copyBytes(header.toByteArray(), result, 0);
    copyBytes(payload.toByteArray(), result, payloadStart);
    // Fix up payload offsets.  We already wrote out the offsets relative to the
    // payload start.  Now that we know what the payload start is, add it to the
    // relative offsets.
    for (int payloadOffset : payloadOffsets) {
      writeOffset(result, payloadOffset,
          payloadStart + readOffset(result, payloadOffset));
    }
    return result;
  }

  // The caller of this method must guarantee that the array sizes and offset
  // value are correct.
  private void copyBytes(byte[] from, byte[] to, int toOffset) {
    for (int i = 0; i < from.length; i += 1) {
      to[toOffset++] = from[i];
    }
  }

  // The caller of this method must guarantee that the array size and offset
  // value are correct.
  private static int readOffset(byte[] result, int index) {
    return (result[index + 0] & 0xff)
        | ((result[index + 1] & 0xff) << 8)
        | ((result[index + 2] & 0xff) << 16)
        | ((result[index + 3] & 0xff) << 24);
  }

  // The caller of this method must guarantee that the array size and offset
  // value are correct.
  private static void writeOffset(byte[] result, int index, int value) {
    result[index + 0] = (byte) (value & 0xff);
    result[index + 1] = (byte) ((value >> 8) & 0xff);
    result[index + 2] = (byte) ((value >> 16) & 0xff);
    result[index + 3] = (byte) ((value >> 24) & 0xff);
  }
}
