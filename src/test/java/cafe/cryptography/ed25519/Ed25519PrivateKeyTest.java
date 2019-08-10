/*
 * This file is part of ed25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.ed25519;

import org.junit.Test;

public class Ed25519PrivateKeyTest {
    @Test
    public void fromByteArrayAcceptsAllBitsSet() {
        // An Ed25519 private key is only ever used as an input to a hash
        // function, not as a scalar, so all 32-byte strings are valid.
        Ed25519PrivateKey
                .fromByteArray(Utils.hexToBytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void fromByteArrayRejectsShortInput() {
        Ed25519PrivateKey.fromByteArray(Utils.hexToBytes("00"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void fromByteArrayRejectsLongInput() {
        Ed25519PrivateKey
                .fromByteArray(Utils.hexToBytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00"));
    }
}
