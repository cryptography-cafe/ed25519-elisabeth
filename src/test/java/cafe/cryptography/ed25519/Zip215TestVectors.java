/*
 * This file is part of ed25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.ed25519;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import cafe.cryptography.curve25519.InvalidEncodingException;
import org.junit.Test;

/**
 * Test against the ZIP 215 test vectors set.
 *
 * We don't explicitly check for success or failure; this is purely informative.
 */
public class Zip215TestVectors {
    public static class TestTuple {
        public static int numCases;
        public int caseNum;
        public byte[] vk;
        public byte[] signature;

        public TestTuple(String line) {
            this.caseNum = ++numCases;
            String[] x = line.split(":");
            this.vk = Utils.hexToBytes(x[0]);
            this.signature = Utils.hexToBytes(x[1]);
        }
    }

    public static Collection<TestTuple> testCases = getTestData("zip215-test-vectors.txt");

    public static Collection<TestTuple> getTestData(String fileName) {
        List<TestTuple> testCases = new ArrayList<TestTuple>();
        BufferedReader file = null;
        try {
            InputStream is = Ed25519TestVectors.class.getClassLoader().getResourceAsStream(fileName);
            if (is == null) {
                throw new IOException("Resource not found: " + fileName);
            }
            file = new BufferedReader(new InputStreamReader(is));
            String line;
            while ((line = file.readLine()) != null) {
                testCases.add(new TestTuple(line));
            }
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        } finally {
            if (file != null) {
                try {
                    file.close();
                } catch (IOException e) {
                }
            }
        }
        return testCases;
    }

    @Test
    public void testVerify() throws InvalidEncodingException {
        for (TestTuple testCase : testCases) {
            Ed25519PublicKey vk = Ed25519PublicKey.fromByteArray(testCase.vk);
            Ed25519Signature sig = Ed25519Signature.fromByteArray(testCase.signature);
            if (vk.verify("Zcash".getBytes(), sig)) {
                // Test case passed
            } else {
                System.out.println("ZIP 215 test case " + testCase.caseNum + " failed");
            }
        }
    }
}