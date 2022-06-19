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

import static org.junit.Assert.assertEquals;

import cafe.cryptography.ed25519.Ed25519PublicKey;
import cafe.cryptography.ed25519.Ed25519Signature;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.HashSet;
import java.util.Set;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/**
 * This test uses test vectors in JSON format to check digital signature schemes. There are still a
 * lot of open questions, e.g. the format for the test vectors is not yet finalized. Therefore, we
 * are not integrating the tests here into other tests
 */
@RunWith(JUnit4.class)
public class JsonSignatureTest {

  /** 
   * Defines the format of the signatures. RAW is used when the signature scheme already
   * defines an encoding (e.g. this is used for RSA signatures).
   */   
  public enum Format { RAW };

  /** Convenience method to get a String from a JsonObject */
  protected static String getString(JsonObject object, String name) {
    return object.get(name).getAsString();
  }

  /** Convenience method to get a byte array from a JsonObject */
  protected static byte[] getBytes(JsonObject object, String name) throws Exception {
    return JsonUtil.asByteArray(object.get(name));
  }

  /**
   * Returns the expected JSON schema for a given test or "" if the schema is undefined.
   * The purpose of this function is to perform a sanity test with the goal to recognize
   * incorrect test setups.
   * @param signatureAlgorithm the signataure algorithm (e.g. "ECDSA")
   * @param signatureFormat the format of the signatures
   * @param verify true if verification is tested, false if signature generations is tested.
   */
  protected static String expectedSchema(String signatureAlgorithm, Format signatureFormat) {
    if (signatureAlgorithm.equals("ED25519")) {
      switch (signatureFormat) {
        case RAW:
          return "eddsa_verify_schema.json";
        default:
          break;
      }
    }
    // If the schema is not defined then the tests below still run. The only drawback is that
    // incorrect test setups are not recognized and will probably lead to failures later.
    return "";
  }
  /**
   * Get a PublicKey from a JsonObject.
   *
   * <p>object contains the key in multiple formats: "key" : elements of the public key "keyDer":
   * the key in ASN encoding encoded hexadecimal "keyPem": the key in Pem format encoded hexadecimal
   * The test can use the format that is most convenient.
   */
  // This is a false positive, since errorprone cannot track values passed into a method.
  @SuppressWarnings("InsecureCryptoUsage")
  protected static Ed25519PublicKey getPublicKey(JsonObject group, String algorithm) throws Exception {
    byte[] encoded = TestUtil.hexToBytes(getString(group.getAsJsonObject("key"), "pk"));
    return Ed25519PublicKey.fromByteArray(encoded);
  }

  /** 
   * Tests the signature verification with test vectors in a given JSON file.
   *
   * <p> Example format for test vectors
   * {
   *   "algorithm": "ECDSA",
   *   "generatorVersion": "0.0a13",
   *   "numberOfTests": 217,
   *   "testGroups": [
   *     {
   *       "key": {
   *         "curve": "secp256r1",
   *         "type": "ECPublicKey",
   *         "wx": "0c9c4bc2617c81eb2dcbfda2db2a370a955be86a0d2e95fcb86a99f90cf046573",
   *         "wy": "0c400363b1b6bcc3595a7d6d3575ccebcbb03f90ba8e58da2bc4824272f4fecff"
   *       },
   *       "keyDer": <X509encoded key>
   *       "keyPem": "-----BEGIN PUBLIC KEY-----\ ... \n-----END PUBLIC KEY-----",
   *       "sha": "SHA-256",
   *       "tests": [
   *         {
   *           "comment": "random signature",
   *           "msg": "48656c6c6f",
   *           "result": "valid",
   *           "sig": "...",
   *           "tcId": 1
   *         },
   *        ...
   * }
   *
   * @param filename the filename of the test vectors
   * @param signatureAlgorithm the algorithm name of the test vectors
   * @param signatureFormat the format of the signatures. This should be Format.P1363 for 
   *        P1363 encoded signatures Format.ASN for ASN.1 encoded signature  and Format.RAW 
            otherwise.  
   * @param allowSkippingKeys if true then keys that cannot be constructed will not fail the test.
   *     This is for example used for files with test vectors that use elliptic curves that are not
   *     commonly supported.
   **/
  public void testVerification(
      String filename, String signatureAlgorithm, Format signatureFormat, boolean allowSkippingKeys)
      throws Exception {
    JsonObject test = JsonUtil.getTestVectors(filename); 
    // Checks whether the test vectors in the file use the expected algorithm and the expected
    // format for the signatures.
    String schema = expectedSchema(signatureAlgorithm, signatureFormat);
    String actualSchema = getString(test, "schema");
    if (!schema.isEmpty() && !schema.equals(actualSchema)) {
      System.out.println(
          signatureAlgorithm
              + ": expecting test vectors with schema "
              + schema
              + " found vectors with schema "
              + actualSchema);
    }
    int numTests = test.get("numberOfTests").getAsInt();
    int cntTests = 0;
    int verifiedSignatures = 0;
    int errors = 0;
    int skippedKeys = 0;
    int skippedAlgorithms = 0;
    int supportedKeys = 0;
    Set<String> skippedGroups = new HashSet<String>();
    for (JsonElement g : test.getAsJsonArray("testGroups")) {
      JsonObject group = g.getAsJsonObject();
      Ed25519PublicKey key = getPublicKey(group, signatureAlgorithm);
      supportedKeys++;
      for (JsonElement t : group.getAsJsonArray("tests")) {
        cntTests++;
        JsonObject testcase = t.getAsJsonObject();
        byte[] message = getBytes(testcase, "msg");
        byte[] signature = getBytes(testcase, "sig");
        int tcid = testcase.get("tcId").getAsInt();
        String sig = TestUtil.bytesToHex(signature);
        String result = getString(testcase, "result");
        boolean verified = false;
        Exception failure = null;
        try {
          Ed25519Signature s = Ed25519Signature.fromByteArray(signature);
          verified = key.verify(message, s);
        } catch (IllegalArgumentException ex) {
          // Ed25519Signature.fromByteArray can throw IllegalArgumentException if
          // the signature is malformed.
          // We don't flag these cases and simply consider the signature as invalid.
          verified = false;
          failure = ex;
        } catch (Exception ex) {
          // Other exceptions (i.e. unchecked exceptions) are considered as error
          // since a third party should never be able to cause such exceptions.
          System.out.println(
              signatureAlgorithm
                  + " signature throws "
                  + ex.toString()
                  + " "
                  + filename
                  + " tcId:"
                  + tcid
                  + " sig:"
                  + sig);
          verified = false;
          failure = ex;
          errors++;
        }
        if (!verified && result.equals("valid")) {
          String reason = "";
          if (failure != null) {
            reason = " reason:" + failure;
          }
          System.out.println(
              "Valid "
                  + signatureAlgorithm
                  + " signature not verified."
                  + " "
                  + filename
                  + " tcId:"
                  + tcid
                  + " sig:"
                  + sig
                  + reason);
          errors++;
        } else if (verified) {
          if (result.equals("invalid")) {
            System.out.println(
                "Invalid"
                    + signatureAlgorithm
                    + " signature verified."
                    + " "
                    + filename
                    + " tcId:"
                    + tcid
                    + " sig:"
                    + sig);
            errors++;
          } else {
            verifiedSignatures++;
          }
        }
      }
    }
    // Prints some information if tests were skipped. This avoids giving
    // the impression that algorithms are supported.
    if (skippedKeys > 0 || skippedAlgorithms > 0 || verifiedSignatures == 0) {
      System.out.println(
          "File:"
              + filename
              + " number of skipped keys:"
              + skippedKeys
              + " number of skipped algorithms:"
              + skippedAlgorithms
              + " number of supported keys:"
              + supportedKeys
              + " verified signatures:"
              + verifiedSignatures);
      for (String s : skippedGroups) {
        System.out.println("Skipped groups where " + s);
      }
    }
    assertEquals(0, errors);
    if (skippedKeys == 0 && skippedAlgorithms == 0) {
      assertEquals(numTests, cntTests);
    }
  }

  @Test
  public void testEd25519Verify() throws Exception {
    testVerification("eddsa_test.json", "ED25519", Format.RAW, true);
  }

}

