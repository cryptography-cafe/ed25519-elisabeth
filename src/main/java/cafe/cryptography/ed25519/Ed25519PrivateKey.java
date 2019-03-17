/*
 * This file is part of ed25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.ed25519;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import cafe.cryptography.curve25519.Scalar;

/**
 * An Ed25519 private key.
 */
public class Ed25519PrivateKey {
    private final byte[] secret;

    private Ed25519PrivateKey(byte[] secret) {
        if (secret.length != 32) {
            throw new IllegalArgumentException("Invalid private key");
        }
        this.secret = Arrays.copyOf(secret, secret.length);
    }

    /**
     * Construct an Ed25519PrivateKey from an array of bytes.
     *
     * @return a private key.
     */
    public static Ed25519PrivateKey fromByteArray(byte[] secret) {
        return new Ed25519PrivateKey(secret);
    }

    /**
     * Encode the public key to its compressed 32-byte form.
     *
     * @return the encoded public key.
     */
    public byte[] toByteArray() {
        return Arrays.copyOf(this.secret, this.secret.length);
    }

    /**
     * Convert this private key into its expanded form, which can be used for
     * creating signatures.
     *
     * @return the expanded private key.
     */
    public Ed25519ExpandedPrivateKey expand() {
        // @formatter:off
        // RFC 8032, section 5.1.6:
        // 1.  Hash the private key, 32 octets, using SHA-512.  Let h denote the
        //     resulting digest.  Construct the secret scalar s from the first
        //     half of the digest, and the corresponding public key A, as
        //     described in the previous section.  Let prefix denote the second
        //     half of the hash digest, h[32],...,h[63].
        //
        // RFC 8032, section 5.1.5:
        // 1.  Hash the 32-byte private key using SHA-512, storing the digest in
        //     a 64-octet large buffer, denoted h.  Only the lower 32 bytes are
        //     used for generating the public key.
        MessageDigest hasher;
        try {
            hasher = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        hasher.update(this.secret);
        byte[] h = hasher.digest();

        byte[] lower = Arrays.copyOfRange(h, 0, 32);
        byte[] upper = Arrays.copyOfRange(h, 32, 64);

        // 2.  Prune the buffer: The lowest three bits of the first octet are
        //     cleared, the highest bit of the last octet is cleared, and the
        //     second highest bit of the last octet is set.
        lower[0] &= 248;
        lower[31] &= 63;
        lower[31] |= 64;

        // 3.  Interpret the buffer as the little-endian integer, forming a
        //     secret scalar s.
        // @formatter:on
        Scalar s = Scalar.fromBits(lower);

        return new Ed25519ExpandedPrivateKey(s, upper);
    }
}
