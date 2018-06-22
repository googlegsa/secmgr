package com.google.enterprise.secmgr.ntlmssp;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import javax.crypto.spec.DESKeySpec;
import javax.xml.bind.DatatypeConverter;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class NtlmCryptoTest {

  private static final String PADDING_BYTE_WITH_PARITY = "FE";
  private static final String[] KEYS_7BYTE = {
    "60cb2922c1d419", "0d83cda38f803b", "2a93c2d902e3b1",
    "00000000000000", "a3bc34ffc24378", "ffffffffffffff"
  };

  @Test
  public void addParityBitsCorrect() throws Exception {
    for (String keyStr : KEYS_7BYTE) {
      byte[] keyWithPadding = DatatypeConverter.parseHexBinary(keyStr + PADDING_BYTE_WITH_PARITY);
      assertFalse(DESKeySpec.isParityAdjusted(keyWithPadding, 0));
      byte[] key = Arrays.copyOfRange(keyWithPadding, 0, 7);
      assertTrue(DESKeySpec.isParityAdjusted(NtlmCrypto.addParityBits(key), 0));
    }
  }

  @Test(expected = NullPointerException.class)
  public void addParityBitsNullKey() throws Exception {
    NtlmCrypto.addParityBits(null);
  }

  @Test
  public void addParityBitsWrongKeySize() throws Exception {
    for (int i = 0; i < 256; i++) {
      if (i != 7) {
        try {
          NtlmCrypto.addParityBits(new byte[i]);
          fail();
        } catch (IllegalArgumentException e) {
        }
      }
    }
  }
}
