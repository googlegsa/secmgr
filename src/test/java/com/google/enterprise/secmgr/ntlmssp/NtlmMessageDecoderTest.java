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
import junit.framework.TestCase;

/**
 * Unit tests to make sure NTLM message decoding works as expected.
 */
public final class NtlmMessageDecoderTest extends TestCase {
  private static final int PAYLOAD_HEADER_LENGTH = 8;
  private static final byte[] BYTES1 =
      new byte[] { (byte) 0xff, (byte) 0xfe, (byte) 0xfd, (byte) 0xfc,
                   (byte) 0xfb, (byte) 0xfa, (byte) 0xf9, (byte) 0xf8 };
  private static final byte[] BYTES2 =
      new byte[] { (byte) 0x80, (byte) 0x81, (byte) 0x82, (byte) 0x83,
                   (byte) 0x87, (byte) 0x86, (byte) 0x85, (byte) 0x84 };

  public void testRead8Ranges() {
    tryRangeRead8(0);
    tryRangeRead8(1);
    tryRangeRead8(0x7f);
    tryRangeRead8(0x80);
    tryRangeRead8(0xff);
  }

  private void tryRangeRead8(int n) {
    byte[] bytes = new byte[] { (byte) n };
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(bytes);
    int decoded;
    try {
      decoded = decoder.read8();
    } catch (UnsupportedEncodingException e) {
      fail(e.getMessage());
      return;
    }
    assertTrue(decoder.atEnd());
    assertEquals(n, decoded);
  }

  public void testRead8AtEnd() {
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(new byte[0]);
    try {
      decoder.read8();
      fail("Expected to see exception");
    } catch (UnsupportedEncodingException e) {
      // pass
    }
  }

  public void testRead16Ranges() {
    tryRangeRead16(0);
    tryRangeRead16(1);
    tryRangeRead16(0x7fff);
    tryRangeRead16(0x8000);
    tryRangeRead16(0xffff);
  }

  private void tryRangeRead16(int n) {
    byte[] bytes = new byte[] { (byte) (n & 0xff), (byte) ((n >> 8) & 0xff) };
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(bytes);
    int decoded;
    try {
      decoded = decoder.read16();
    } catch (UnsupportedEncodingException e) {
      fail(e.getMessage());
      return;
    }
    assertTrue(decoder.atEnd());
    assertEquals(n, decoded);
  }

  public void testRead16AtEnd() {
    tryRead16AtEnd(new byte[0]);
    tryRead16AtEnd(new byte[1]);
  }

  private void tryRead16AtEnd(byte[] bytes) {
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(bytes);
    try {
      decoder.read16();
      fail("Expected to see exception");
    } catch (UnsupportedEncodingException e) {
      // pass
    }
  }

  public void testRead32Ranges() {
    tryRangeRead32(0);
    tryRangeRead32(1);
    tryRangeRead32(0x7fff);
    tryRangeRead32(0x8000);
    tryRangeRead32(0xffff);
  }

  private void tryRangeRead32(int n) {
    byte[] bytes
        = new byte[] { (byte) (n & 0xff),
                       (byte) ((n >> 8) & 0xff),
                       (byte) ((n >> 16) & 0xff),
                       (byte) ((n >> 24) & 0xff) };
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(bytes);
    int decoded;
    try {
      decoded = decoder.read32();
    } catch (UnsupportedEncodingException e) {
      fail(e.getMessage());
      return;
    }
    assertTrue(decoder.atEnd());
    assertEquals(n, decoded);
  }

  public void testRead32AtEnd() {
    tryRead32AtEnd(new byte[0]);
    tryRead32AtEnd(new byte[1]);
    tryRead32AtEnd(new byte[2]);
    tryRead32AtEnd(new byte[3]);
  }

  private void tryRead32AtEnd(byte[] bytes) {
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(bytes);
    try {
      decoder.read32();
      fail("Expected to see exception");
    } catch (UnsupportedEncodingException e) {
      // pass
    }
  }

  public void testReadBytes()
      throws UnsupportedEncodingException {
    for (int i = 0; i <= BYTES1.length; i += 1) {
      NtlmMessageDecoder decoder = NtlmMessageDecoder.make(BYTES1);
      byte[] actual = decoder.readBytes(i);
      assertEquals(i, decoder.getIndex());
      if (i < BYTES1.length) {
        assertFalse(decoder.atEnd());
      } else {
        assertTrue(decoder.atEnd());
      }
      compareBytes(BYTES1, i, actual);
    }
  }

  public void testReadBytesAtEnd() {
    tryReadBytesAtEnd(0, 1);
    tryReadBytesAtEnd(0, 2);
    tryReadBytesAtEnd(1, 2);
    tryReadBytesAtEnd(1, 3);
    tryReadBytesAtEnd(2, 3);
    tryReadBytesAtEnd(2, 4);
  }

  private void tryReadBytesAtEnd(int m, int n) {
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(new byte[m]);
    try {
      decoder.readBytes(m + n);
      fail("Expected to see exception");
    } catch (UnsupportedEncodingException e) {
      // pass
    }
  }

  public void testSkip()
      throws UnsupportedEncodingException {
    for (int i = 0; i <= BYTES1.length; i += 1) {
      NtlmMessageDecoder decoder = NtlmMessageDecoder.make(BYTES1);
      decoder.skip(i);
      assertEquals(i, decoder.getIndex());
      if (i < BYTES1.length) {
        assertFalse(decoder.atEnd());
        assertEquals(BYTES1[i] & 0xff, decoder.read8());
      } else {
        assertTrue(decoder.atEnd());
      }
    }
  }

  public void testSkipAtEnd() {
    trySkipAtEnd(0, 1);
    trySkipAtEnd(0, 2);
    trySkipAtEnd(1, 2);
    trySkipAtEnd(1, 3);
    trySkipAtEnd(2, 3);
    trySkipAtEnd(2, 4);
  }

  private void trySkipAtEnd(int m, int n) {
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(new byte[m]);
    try {
      decoder.skip(m + n);
      fail("Expected to see exception");
    } catch (UnsupportedEncodingException e) {
      // pass
    }
  }

  public void testSinglePayload()
      throws UnsupportedEncodingException {
    for (int i = 0; i <= BYTES1.length; i += 1) {
      trySinglePayload(BYTES1, i);
      for (int j = i; j < BYTES1.length; j += 1) {
        trySinglePayload(extractBytes(BYTES1, j), i);
      }
    }
  }

  private void trySinglePayload(byte[] payload, int len)
      throws UnsupportedEncodingException {
    byte[] header = makePayloadHeader(len, payload.length, PAYLOAD_HEADER_LENGTH);
    NtlmMessageDecoder decoder = NtlmMessageDecoder.make(appendBytes(header, payload));
    byte[] actual = decoder.readPayload();
    assertEquals(PAYLOAD_HEADER_LENGTH, decoder.getIndex());
    assertTrue(decoder.atEnd());
    compareBytes(payload, len, actual);
  }

  public void testDoublePayload()
      throws UnsupportedEncodingException {
    for (int i1 = 0; i1 <= BYTES1.length; i1 += 1) {
      for (int i2 = 0; i2 <= BYTES2.length; i2 += 1) {
        tryDoublePayload(BYTES1, i1, BYTES2, i2);
        for (int j1 = i1; j1 < BYTES1.length; j1 += 1) {
          for (int j2 = i2; j2 < BYTES2.length; j2 += 1) {
            tryDoublePayload(
                extractBytes(BYTES1, j1), i1,
                extractBytes(BYTES2, j2), i2);
          }
        }
      }
    }
  }

  private void tryDoublePayload(byte[] payload1, int len1, byte[] payload2, int len2)
      throws UnsupportedEncodingException {
    int twoHeaders = PAYLOAD_HEADER_LENGTH * 2;
    byte[] header1 = makePayloadHeader(len1, payload1.length, twoHeaders);
    byte[] header2 = makePayloadHeader(len2, payload2.length, twoHeaders + payload1.length);
    NtlmMessageDecoder decoder
        = NtlmMessageDecoder.make(appendBytes(header1, header2, payload1, payload2));

    byte[] actual1 = decoder.readPayload();
    assertEquals(PAYLOAD_HEADER_LENGTH, decoder.getIndex());
    assertFalse(decoder.atEnd());
    compareBytes(payload1, len1, actual1);

    byte[] actual2 = decoder.readPayload();
    assertEquals(twoHeaders, decoder.getIndex());
    assertTrue(decoder.atEnd());
    compareBytes(payload2, len2, actual2);
  }

  private byte[] makePayloadHeader(int len, int maxLen, int offset) {
    return new byte[] {
      (byte) (len & 0xff),
      (byte) ((len >> 8) & 0xff),
      (byte) (maxLen & 0xff),
      (byte) ((maxLen >> 8) & 0xff),
      (byte) (offset & 0xff),
      (byte) ((offset >> 8) & 0xff),
      (byte) ((offset >> 16) & 0xff),
      (byte) ((offset >> 24) & 0xff)
    };
  }

  private byte[] appendBytes(byte[]... arrays) {
    int n = 0;
    for (byte[] array : arrays) {
      n += array.length;
    }
    byte[] result = new byte[n];
    int i = 0;
    for (byte[] array : arrays) {
      for (byte b : array) {
        result[i++] = b;
      }
    }
    return result;
  }

  private void compareBytes(byte[] expected, int len, byte[] actual) {
    assertNotNull(actual);
    assertEquals(len, actual.length);
    for (int i = 0; i < len; i += 1) {
      assertEquals(expected[i], actual[i]);
    }
  }

  private byte[] extractBytes(byte[] expected, int len) {
    byte[] result = new byte[len];
    for (int i = 0; i < len; i += 1) {
      result[i] = expected[i];
    }
    return result;
  }
}
