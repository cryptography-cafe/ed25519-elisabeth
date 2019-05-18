/*
 * This file is part of ed25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.ed25519;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import cafe.cryptography.curve25519.CompressedEdwardsY;
import cafe.cryptography.curve25519.EdwardsPoint;
import cafe.cryptography.curve25519.InvalidEncodingException;
import cafe.cryptography.curve25519.Scalar;

/**
 * An Ed25519 public key.
 */
public class Ed25519PublicKey {
    private final EdwardsPoint A;
    private final CompressedEdwardsY Aenc;

    Ed25519PublicKey(EdwardsPoint A) {
        this.A = A;
        this.Aenc = A.compress();
    }

    private Ed25519PublicKey(CompressedEdwardsY Aenc) throws InvalidEncodingException {
        this.Aenc = Aenc;
        this.A = Aenc.decompress();
    }

    /**
     * Construct an Ed25519PublicKey from an array of bytes.
     *
     * @return a public key.
     * @throws InvalidEncodingException if the input is not a valid encoding.
     */
    public static Ed25519PublicKey fromByteArray(byte[] input) throws InvalidEncodingException {
        CompressedEdwardsY Aenc = new CompressedEdwardsY(input);
        return new Ed25519PublicKey(Aenc);
    }

    /**
     * Encode the public key to its compressed 32-byte form.
     *
     * @return the encoded public key.
     */
    public byte[] toByteArray() {
        return this.Aenc.toByteArray();
    }

    /**
     * Verify a signature over a message with this public key.
     *
     * @return true if the signature is valid, false otherwise.
     */
    public boolean verify(byte[] message, Ed25519Signature signature) {
        return this.verify(message, 0, message.length, signature);
    }

    /**
     * Verify a signature over a message with this public key.
     *
     * @return true if the signature is valid, false otherwise.
     */
    public boolean verify(byte[] message, int offset, int length, Ed25519Signature signature) {
        // @formatter:off
        // RFC 8032, section 5.1:
        //   PH(x)   | x (i.e., the identity function)
        //   For Ed25519, dom2(f,c) is the empty string.

        // RFC 8032, section 5.1.7:
        // 2.  Compute SHA512(dom2(F, C) || R || A || PH(M)), and interpret the
        //     64-octet digest as a little-endian integer k.
        // @formatter:on
        MessageDigest h;
        try {
            h = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        h.update(signature.R.toByteArray());
        h.update(this.Aenc.toByteArray());
        h.update(message, offset, length);
        Scalar k = Scalar.fromBytesModOrderWide(h.digest());

        // @formatter:off
        // 3.  Check the group equation [8][S]B = [8]R + [8][k]A'. It's
        //     sufficient, but not required, to instead check [S]B = R + [k]A'.
        // @formatter:on
        EdwardsPoint Aneg = this.A.negate();
        EdwardsPoint R = EdwardsPoint.vartimeDoubleScalarMultiplyBasepoint(k, Aneg, signature.S);
        return R.compress().equals(signature.R);
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Ed25519PublicKey)) {
            return false;
        }

        Ed25519PublicKey other = (Ed25519PublicKey) obj;
        return this.Aenc.equals(other.Aenc);
    }

    @Override
    public int hashCode() {
        return this.Aenc.hashCode();
    }
}
