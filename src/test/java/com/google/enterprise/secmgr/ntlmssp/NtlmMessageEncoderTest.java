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

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import junit.framework.TestCase;

/**
 * Unit tests to ensure that NTLM messages are properly encoded.
 */
public final class NtlmMessageEncoderTest extends TestCase {
  private static final int PAYLOAD_HEADER_LENGTH = 8;
  private static final byte[] EMPTY = new byte[0];
  private static final byte[] EXPECTED =
      new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

  public void testWrite8Ranges() {
    tryGoodRangeWrite8(0);
    tryGoodRangeWrite8(1);
    tryGoodRangeWrite8(127);
    tryGoodRangeWrite8(128);
    tryGoodRangeWrite8(255);
    tryBadRangeWrite8(256);
    tryBadRangeWrite8(-1);
    tryBadRangeWrite8(-128);
    tryBadRangeWrite8(-129);
  }

  private void tryGoodRangeWrite8(int n) {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    try {
      encoder.write8(n);
    } catch (UnsupportedEncodingException e) {
      fail("Method should not have signalled exception");
    }
  }

  private void tryBadRangeWrite8(int n) {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    try {
      encoder.write8(n);
      fail("Method should have signalled exception");
    } catch (UnsupportedEncodingException e) {
      // pass
    }
  }

  public void testWrite16Ranges() {
    tryGoodRangeWrite16(0);
    tryGoodRangeWrite16(1);
    tryGoodRangeWrite16(0x7fff);
    tryGoodRangeWrite16(0x8000);
    tryGoodRangeWrite16(0xffff);
    tryBadRangeWrite16(0x10000);
    tryBadRangeWrite16(-1);
    tryBadRangeWrite16(-0x7fff);
    tryBadRangeWrite16(-0x8000);
    tryBadRangeWrite16(-0x8001);
  }

  private void tryGoodRangeWrite16(int n) {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    try {
      encoder.write16(n);
    } catch (UnsupportedEncodingException e) {
      fail("Method should not have signalled exception");
    }
  }

  private void tryBadRangeWrite16(int n) {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    try {
      encoder.write16(n);
      fail("Method should have signalled exception");
    } catch (UnsupportedEncodingException e) {
      // pass
    }
  }

  public void testWrite32Ranges() {
    tryGoodRangeWrite32(0);
    tryGoodRangeWrite32(1);
    tryGoodRangeWrite32(0x7fffffff);
    tryGoodRangeWrite32(0x80000000);
    tryGoodRangeWrite32(0xffffffff);
    tryGoodRangeWrite32(-1);
    tryGoodRangeWrite32(-0x7fffffff);
    tryGoodRangeWrite32(-0x80000000);
  }

  private void tryGoodRangeWrite32(int n) {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    encoder.write32(n);
  }

  public void testWrite8Encoding()
      throws UnsupportedEncodingException {
    tryWrite8Encoding(0);
    tryWrite8Encoding(1);
    tryWrite8Encoding(0x7f);
    tryWrite8Encoding(0x80);
    tryWrite8Encoding(0xff);
  }

  private void tryWrite8Encoding(int n)
      throws UnsupportedEncodingException {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    encoder.write8(n);
    byte[] bytes = encoder.getBytes();
    assertEquals(1, bytes.length);
    assertEquals(n, bytes[0] & 0xff);
  }

  public void testWrite16Encoding()
      throws UnsupportedEncodingException {
    tryWrite16Encoding(0);
    tryWrite16Encoding(1);
    tryWrite16Encoding(0x7fff);
    tryWrite16Encoding(0x8000);
    tryWrite16Encoding(0xffff);
  }

  private void tryWrite16Encoding(int n)
      throws UnsupportedEncodingException {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    encoder.write16(n);
    byte[] bytes = encoder.getBytes();
    assertEquals(2, bytes.length);
    assertEquals(n & 0xff, bytes[0] & 0xff);
    assertEquals((n >> 8) & 0xff, bytes[1] & 0xff);
  }

  public void testWrite32Encoding() {
    tryWrite32Encoding(0);
    tryWrite32Encoding(1);
    tryWrite32Encoding(0x7fffffff);
    tryWrite32Encoding(0x80000000);
    tryWrite32Encoding(0xffffffff);
  }

  private void tryWrite32Encoding(int n) {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    encoder.write32(n);
    byte[] bytes = encoder.getBytes();
    assertEquals(4, bytes.length);
    assertEquals(n & 0xff, bytes[0] & 0xff);
    assertEquals((n >> 8) & 0xff, bytes[1] & 0xff);
    assertEquals((n >> 16) & 0xff, bytes[2] & 0xff);
    assertEquals((n >> 24) & 0xff, bytes[3] & 0xff);
  }

  public void testWriteIntCombo()
      throws UnsupportedEncodingException {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    encoder.write8(0x01);
    encoder.write16(0x0302);
    encoder.write32(0x07060504);
    byte[] encoded = encoder.getBytes();
    assertTrue(Arrays.equals(EXPECTED, encoded));
  }

  public void testWriteBytesNull() {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    encoder.writeBytes(null);
    byte[] encoded = encoder.getBytes();
    assertEquals(0, encoded.length);
  }

  public void testWriteBytesEmpty() {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    encoder.writeBytes(EMPTY);
    byte[] encoded = encoder.getBytes();
    assertEquals(0, encoded.length);
  }

  public void testWriteBytesSimple() {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    encoder.writeBytes(EXPECTED);
    byte[] encoded = encoder.getBytes();
    assertTrue(Arrays.equals(EXPECTED, encoded));
  }

  public void testWritePayloadNull()
      throws UnsupportedEncodingException {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    encoder.writePayload(null);
    byte[] encoded = encoder.getBytes();
    assertEquals(PAYLOAD_HEADER_LENGTH, encoded.length);
    checkPayloadHeader(0, 0, PAYLOAD_HEADER_LENGTH, encoded, 0);
  }

  public void testWritePayloadEmpty()
      throws UnsupportedEncodingException {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    encoder.writePayload(EMPTY);
    byte[] encoded = encoder.getBytes();
    assertEquals(PAYLOAD_HEADER_LENGTH, encoded.length);
    checkPayloadHeader(0, 0, PAYLOAD_HEADER_LENGTH, encoded, 0);
  }

  public void testWritePayloadSimple()
      throws UnsupportedEncodingException {
    NtlmMessageEncoder encoder = NtlmMessageEncoder.make();
    encoder.writePayload(EXPECTED);
    byte[] encoded = encoder.getBytes();
    assertEquals(PAYLOAD_HEADER_LENGTH + EXPECTED.length, encoded.length);
    checkPayloadHeader(EXPECTED.length, EXPECTED.length, PAYLOAD_HEADER_LENGTH, encoded, 0);
    checkBytes(EXPECTED, encoded, PAYLOAD_HEADER_LENGTH);
  }

  private void checkPayloadHeader(int j, int k, int l, byte[] actual, int offset) {
    assertEquals(j & 0xff, actual[offset++]);
    assertEquals((j >> 8) & 0xff, actual[offset++]);
    assertEquals(k & 0xff, actual[offset++]);
    assertEquals((k >> 8) & 0xff, actual[offset++]);
    assertEquals(l & 0xff, actual[offset++]);
    assertEquals((l >> 8) & 0xff, actual[offset++]);
    assertEquals((l >> 16) & 0xff, actual[offset++]);
    assertEquals((l >> 24) & 0xff, actual[offset++]);
  }

  private void checkBytes(byte[] expected, byte[] actual, int offset) {
    for (byte b : expected) {
      assertEquals(b, actual[offset++]);
    }
  }
}
