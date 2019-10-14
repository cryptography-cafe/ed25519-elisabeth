/*
 * This file is part of ed25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.ed25519;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import cafe.cryptography.curve25519.CompressedEdwardsY;
import cafe.cryptography.curve25519.Scalar;

/**
 * An Ed25519 signature.
 */
public class Ed25519Signature {
    final CompressedEdwardsY R;
    final Scalar S;

    Ed25519Signature(CompressedEdwardsY R, Scalar S) {
        this.R = R;
        this.S = S;
    }

    /**
     * Construct an Ed25519Signature from an array of bytes.
     *
     * @return a signature.
     */
    public static Ed25519Signature fromByteArray(byte[] input) {
        if (input.length != 64) {
            throw new IllegalArgumentException("signature length is wrong");
        }

        // RFC 8032, section 5.1.7:
        // @formatter:off
        // 1. To verify a signature [...], first split the signature into two
        //    32-octet halves.  Decode the first half as a point R, and the
        //    second half as an integer S, in the range 0 <= s < L.  [...] If
        //    any of the decodings fail (including S being out of range), the
        //    signature is invalid.
        // @formatter:on
        CompressedEdwardsY R = new CompressedEdwardsY(Arrays.copyOfRange(input, 0, 32));

        // If the four most significant bits are unset, we know the scalar is
        // guaranteed to be fully reduced modulo the order of the basepoint, and
        // thus we can skip the full check.
        Scalar S;
        if ((input[63] & 240) == 0) {
          S = Scalar.fromBits(Arrays.copyOfRange(input, 32, 64));
        } else {
          S = Scalar.fromCanonicalBytes(Arrays.copyOfRange(input, 32, 64));
        }

        return new Ed25519Signature(R, S);
    }

    /**
     * Convert this signature to an array of bytes.
     *
     * @return the encoded signature.
     */
    public byte[] toByteArray() {
        // RFC 8032, section 5.1.6:
        // @formatter:off
        // 6.  Form the signature of the concatenation of R (32 octets) and the
        //     little-endian encoding of S (32 octets; the three most
        //     significant bits of the final octet are always zero).
        // @formatter:on
        byte[] Rbar = this.R.toByteArray();
        byte[] Sbar = this.S.toByteArray();
        byte[] sig = new byte[Rbar.length + Sbar.length];
        System.arraycopy(Rbar, 0, sig, 0, Rbar.length);
        System.arraycopy(Sbar, 0, sig, Rbar.length, Sbar.length);
        return sig;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof Ed25519Signature)) {
            return false;
        }

        Ed25519Signature other = (Ed25519Signature) obj;
        return this.R.equals(other.R) && this.S.equals(other.S);
    }

    @Override
    public int hashCode() {
        return this.R.hashCode() ^ this.S.hashCode();
    }
}
