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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Test against the medium test vectors set.
 *
 * TESTVECTORS is taken from ed25519-dalek, which in turn obtained it from
 * sign.input.gz in agl's ed25519 Golang package. It is a selection of test
 * cases from https://ed25519.cr.yp.to/python/sign.input
 */
public class Ed25519TestVectors {
    public static class TestTuple {
        public static int numCases;
        public int caseNum;
        public byte[] sk;
        public byte[] vk;
        public byte[] message;
        public byte[] signature;

        public TestTuple(String line) {
            this.caseNum = ++numCases;
            String[] x = line.split(":");
            this.sk = Utils.hexToBytes(x[0].substring(0, 64));
            this.vk = Utils.hexToBytes(x[1]);
            this.message = Utils.hexToBytes(x[2]);
            this.signature = Utils.hexToBytes(x[3].substring(0, 128));
        }
    }

    public static Collection<TestTuple> testCases = getTestData("TESTVECTORS");

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
    public void derivePublic() {
        for (TestTuple testCase : testCases) {
            Ed25519PrivateKey sk = Ed25519PrivateKey.fromByteArray(testCase.sk);
            assertThat("Test case " + testCase.caseNum + " failed", sk.derivePublic().toByteArray(), is(testCase.vk));
        }
    }

    @Test
    public void testSign() {
        for (TestTuple testCase : testCases) {
            Ed25519PrivateKey sk = Ed25519PrivateKey.fromByteArray(testCase.sk);
            assertThat("Test case " + testCase.caseNum + " failed",
                    sk.expand().sign(testCase.message, sk.derivePublic()).toByteArray(), is(testCase.signature));
        }
    }

    @Test
    public void testVerify() throws InvalidEncodingException {
        for (TestTuple testCase : testCases) {
            Ed25519PublicKey vk = Ed25519PublicKey.fromByteArray(testCase.vk);
            Ed25519Signature sig = Ed25519Signature.fromByteArray(testCase.signature);
            assertTrue("Test case " + testCase.caseNum + " failed", vk.verify(testCase.message, sig));
        }
    }
}
