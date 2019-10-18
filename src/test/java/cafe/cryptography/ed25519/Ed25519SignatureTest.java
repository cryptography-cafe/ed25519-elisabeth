/*
 * This file is part of ed25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.ed25519;

import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

public class Ed25519SignatureTest {
    @Test
    public void fromByteArrayAcceptsInvalidR() {
        // Validation of R happens during signature verification
        Ed25519Signature.fromByteArray(Utils.hexToBytes(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void fromByteArrayRejectsShortInput() {
        Ed25519Signature.fromByteArray(Utils.hexToBytes("00"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void fromByteArrayRejectsLongInput() {
        Ed25519Signature.fromByteArray(Utils.hexToBytes(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000ff"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void fromByteArrayRejectsNonCanonicalS() {
        Ed25519Signature.fromByteArray(Utils.hexToBytes(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    }

    @Test
    public void fromByteArraySucceedsFastS() {
        Ed25519Signature.fromByteArray(Utils.hexToBytes(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f"));
    }
}
