/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.security.wycheproof;

/** Test utilities */
public class TestUtil {

  public static String bytesToHex(byte[] bytes) {
    // bytesToHex is used to convert output from Cipher.
    // cipher.update can return null, which is equivalent to returning
    // no plaitext rsp. ciphertext.
    if (bytes == null) {
      return "";
    }
    String chars = "0123456789abcdef";
    StringBuilder result = new StringBuilder(2 * bytes.length);
    for (byte b : bytes) {
      // convert to unsigned
      int val = b & 0xff;
      result.append(chars.charAt(val / 16));
      result.append(chars.charAt(val % 16));
    }
    return result.toString();
  }

  public static byte[] hexToBytes(String hex) throws IllegalArgumentException {
    if (hex.length() % 2 != 0) {
      throw new IllegalArgumentException("Expected a string of even length");
    }
    int size = hex.length() / 2;
    byte[] result = new byte[size];
    for (int i = 0; i < size; i++) {
      int hi = Character.digit(hex.charAt(2 * i), 16);
      int lo = Character.digit(hex.charAt(2 * i + 1), 16);
      if ((hi == -1) || (lo == -1)) {
        throw new IllegalArgumentException("input is not hexadecimal");
      }
      result[i] = (byte) (16 * hi + lo);
    }
    return result;
  }
}
