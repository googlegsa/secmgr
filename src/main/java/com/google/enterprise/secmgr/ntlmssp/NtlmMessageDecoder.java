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

import javax.annotation.concurrent.NotThreadSafe;

/**
 * An abstraction for decoding NTLM messages.  The strategy is to decode the
 * message one element at a time.  Payload indices are carefully checked for
 * consistency to make sure that they are in the header.
 */
@NotThreadSafe
final class NtlmMessageDecoder {
  private final byte[] message;
  private int index;
  private int payloadStart;

  public static NtlmMessageDecoder make(byte[] message) {
    Preconditions.checkNotNull(message);
    return new NtlmMessageDecoder(message);
  }

  private NtlmMessageDecoder(byte[] message) {
    this.message = message;
    index = 0;
    payloadStart = message.length;
  }

  public boolean atEnd() {
    return index == payloadStart;
  }

  public int getIndex() {
    return index;
  }

  public int read8()
      throws UnsupportedEncodingException {
    checkHeaderIndex(1);
    return message[index++] & 0xff;
  }

  public int read16()
      throws UnsupportedEncodingException {
    checkHeaderIndex(2);
    byte b0 = message[index++];
    byte b1 = message[index++];
    return (b0 & 0xff)
        | ((b1 & 0xff) << 8);
  }

  public int read32()
      throws UnsupportedEncodingException {
    checkHeaderIndex(4);
    int b0 = message[index++];
    int b1 = message[index++];
    int b2 = message[index++];
    int b3 = message[index++];
    return (b0 & 0xff)
        | ((b1 & 0xff) << 8)
        | ((b2 & 0xff) << 16)
        | ((b3 & 0xff) << 24);
  }

  public byte[] readBytes(int n)
      throws UnsupportedEncodingException {
    Preconditions.checkArgument(n >= 0);
    checkHeaderIndex(n);
    byte[] result = new byte[n];
    for (int j = 0; j < n; j += 1) {
      result[j] = message[index++];
    }
    return result;
  }

  public void skip(int n)
      throws UnsupportedEncodingException {
    Preconditions.checkArgument(n >= 0);
    checkHeaderIndex(n);
    index += n;
  }

  private void checkHeaderIndex(int n)
      throws UnsupportedEncodingException {
    if ((index + n) > payloadStart) {
      throw new UnsupportedEncodingException("Header read exceeds end of message");
    }
  }

  public byte[] readPayload()
      throws UnsupportedEncodingException {
    return readPayload(readPayloadHeader());
  }

  public PayloadHeader readPayloadHeader()
      throws UnsupportedEncodingException {
    int len = read16();
    int maxLen = read16();
    int offset = read32();
    return new PayloadHeader(len, maxLen, offset);
  }

  public byte[] readPayload(PayloadHeader header)
      throws UnsupportedEncodingException {
    int offset = header.offset;
    checkPayloadOffset(offset, header.maxLen);
    byte[] result = new byte[header.len];
    for (int j = 0; j < header.len; j += 1) {
      result[j] = message[offset++];
    }
    return result;
  }

  public static final class PayloadHeader {
    public final int len;
    public final int maxLen;
    public final int offset;

    private PayloadHeader(int len, int maxLen, int offset) {
      this.len = len;
      this.maxLen = maxLen;
      this.offset = offset;
    }
  }

  public void skipPayloadHeader() {
    index += 8;
  }

  // May change payloadStart to start if the latter is smaller.
  private void checkPayloadOffset(int start, int n)
      throws UnsupportedEncodingException {
    if (n == 0) {
      return;
    }
    if (start < 0) {
      throw new UnsupportedEncodingException("Payload start too big to fit in int: " + start);
    }
    if (start < index) {
      throw new UnsupportedEncodingException("Payload read in header: " + start);
    }
    if ((start + n) > message.length) {
      throw new UnsupportedEncodingException("Payload read exceeds end of message: " + start);
    }
    if (start < payloadStart) {
      payloadStart = start;
    }
  }
}
