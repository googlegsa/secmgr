// Copyright 2018 Google Inc.
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
package com.google.enterprise.sessionmanager;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.nio.charset.Charset;

/**
 * Common utility methods
 * */
public class Utils {

  /**
   * Converts utf8-encoded data to a String.
   *
   * @param  data The bytes to be decoded into characters
   * @return a String containing the converted chars.
   *
   * came from java/com/google/io/protocol/ProtocolSupport.java
   */
  public static String toStringUtf8(byte[] data) {
    return (data != null) ? toStringUtf8(data, 0, data.length) : null;
  }

  /**
   * Converts utf8-encoded data to a String.
   *
   * @param  data The bytes to be decoded into characters
   * @param  offset The index of the first byte to decode
   * @param  length The number of bytes to decode
   * @return a String containing the converted chars.
   *
   * * came from java/com/google/io/protocol/ProtocolSupport.java
   */
  public static String toStringUtf8(byte[] data, int offset, int length) {
    return (data == null) ? null
        : (length == 0) ? "" : new String(data, offset, length, UTF_8);
  }

  public static byte[] toBytes(String str, Charset charset) {
    return str != null ? str.getBytes(charset) : null;
  }

  public static byte[] toBytesUtf8(String str) {
    return toBytes(str, UTF_8);
  }

  private Utils() {
  }
}
