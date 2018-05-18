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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@ThreadSafe
final class NtlmCrypto extends NtlmBase {

  private static final String MD4_ALGORITHM = "MD4";
  private static final String MD5_ALGORITHM = "MD5";
  private static final String DES_KEY_ALGORITHM = "DES";
  private static final String DES_ALGORITHM = "DES/ECB/NoPadding";
  private static final String LM_MAGIC_STRING = "KGS!@#$%";
  private static final SecureRandom prng = new SecureRandom();

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  // Don't instantiate.
  private NtlmCrypto() {
    throw new UnsupportedOperationException();
  }

  static byte[] generateNonce(int nBytes) {
    byte[] nonce = new byte[nBytes];
    synchronized (prng) {
      prng.nextBytes(nonce);
    }
    return nonce;
  }

  static byte[] generateNtV2ChallengeResponse(
      byte[] serverNonce, byte[] clientNonce, String password)
      throws GeneralSecurityException, UnsupportedEncodingException {
    Preconditions.checkNotNull(serverNonce);
    Preconditions.checkArgument(serverNonce.length == 8);
    Preconditions.checkNotNull(clientNonce);
    Preconditions.checkArgument(clientNonce.length == 8);
    Preconditions.checkNotNull(password);
    Preconditions.checkArgument(!password.isEmpty());
    Cipher des = Cipher.getInstance(DES_ALGORITHM);

    MessageDigest md4 = MessageDigest.getInstance(MD4_ALGORITHM);
    byte[] keyBytes = md4.digest(password.getBytes(UNICODE_CHARSET));

    MessageDigest md5 = MessageDigest.getInstance(MD5_ALGORITHM);
    byte[] combinedNonce = Arrays.copyOf(md5.digest(concatenate(serverNonce, clientNonce)), 8);

    return runDesl(des, combinedNonce, keyBytes);
  }

  static byte[] generateNtChallengeResponse(byte[] nonce, String password)
      throws GeneralSecurityException, UnsupportedEncodingException {
    Preconditions.checkNotNull(nonce);
    Preconditions.checkArgument(nonce.length == 8);
    Preconditions.checkNotNull(password);
    Preconditions.checkArgument(!password.isEmpty());
    Cipher des = Cipher.getInstance(DES_ALGORITHM);

    MessageDigest md4 = MessageDigest.getInstance(MD4_ALGORITHM);
    byte[] keyBytes = md4.digest(password.getBytes(UNICODE_CHARSET));

    return runDesl(des, nonce, keyBytes);
  }

  static byte[] generateLmChallengeResponse(byte[] nonce, String password)
      throws GeneralSecurityException, UnsupportedEncodingException {
    Preconditions.checkNotNull(nonce);
    Preconditions.checkArgument(nonce.length == 8);
    Preconditions.checkNotNull(password);
    Preconditions.checkArgument(!password.isEmpty());
    Cipher des = Cipher.getInstance(DES_ALGORITHM);

    byte[] pBytes = Arrays.copyOf(password.toUpperCase().getBytes(oemCharset), 14);
    byte[] keyBytes = new byte[16];
    byte[] magicNonce = LM_MAGIC_STRING.getBytes("US-ASCII");
    runDes(des, magicNonce, keyBytes, 0, pBytes, 0);
    runDes(des, magicNonce, keyBytes, 8, pBytes, 7);

    return runDesl(des, nonce, keyBytes);
  }

  private static byte[] runDesl(Cipher des, byte[] nonce, byte[] keyBytes)
      throws GeneralSecurityException {
    byte[] result = new byte[24];
    runDes(des, nonce, result, 0, keyBytes, 0);
    runDes(des, nonce, result, 8, keyBytes, 7);
    runDes(des, nonce, result, 16, keyBytes, 14);
    return result;
  }

  private static void runDes(Cipher des, byte[] nonce, byte[] result, int resultIndex,
      byte[] keyBytes, int keyIndex)
      throws GeneralSecurityException {
    byte[] subKey = Arrays.copyOfRange(keyBytes, keyIndex, keyIndex + 7);
    des.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(addParityBits(subKey), DES_KEY_ALGORITHM));
    System.arraycopy(des.doFinal(nonce), 0, result, resultIndex, 8);
  }

  private static byte[] concatenate(byte[] prefix, byte[] suffix) {
    byte[] result = new byte[prefix.length + suffix.length];
    System.arraycopy(prefix, 0, result, 0, prefix.length);
    System.arraycopy(suffix, 0, result, prefix.length, suffix.length);
    return result;
  }

  /**
   * Add parity bits to a DES key: a parity bit is added after each 7th bits of the 56bit input
   * key, making it a valid 64bit DES key.
   *
   * @param key56bit key without parity bits
   * @return key with parity bits added
   */
  @VisibleForTesting
  static byte[] addParityBits(byte[] key56bit) {
    Preconditions.checkNotNull(key56bit);
    Preconditions.checkArgument(key56bit.length == 7);

    byte[] key64bit = new byte[8];

    int bitPos = 1;
    int bitCount = 0;

    for (int i = 0; i < 56; i++) {
      boolean bit = (key56bit[6 - i / 8] & (1 << (i % 8))) > 0;

      if (bit) {
        key64bit[7 - bitPos / 8] |= (1 << (bitPos % 8)) & 0xFF;
        bitCount++;
      }

      if ((i + 1) % 7 == 0) {
        if (bitCount % 2 == 0) {
          key64bit[7 - bitPos / 8] |= 1;
        }
        bitPos++;
        bitCount = 0;
      }
      bitPos++;
    }
    return key64bit;
  }
}
