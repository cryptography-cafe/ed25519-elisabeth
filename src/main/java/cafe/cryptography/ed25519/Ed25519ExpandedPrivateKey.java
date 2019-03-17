/*
 * This file is part of ed25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.ed25519;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import cafe.cryptography.curve25519.CompressedEdwardsY;
import cafe.cryptography.curve25519.Constants;
import cafe.cryptography.curve25519.EdwardsPoint;
import cafe.cryptography.curve25519.Scalar;

/**
 * An Ed25519 expanded private key.
 */
public class Ed25519ExpandedPrivateKey {
    private final Scalar s;
    private final byte[] prefix;

    Ed25519ExpandedPrivateKey(Scalar s, byte[] prefix) {
        this.s = s;
        this.prefix = prefix;
    }

    /**
     * Sign a message with this expanded private key.
     *
     * @return the signature.
     */
    public Ed25519Signature sign(byte[] message, Ed25519PublicKey publicKey) {
        // @formatter:off
        // RFC 8032, section 5.1:
        //   PH(x)   | x (i.e., the identity function)
        //   For Ed25519, dom2(f,c) is the empty string.

        // RFC 8032, section 5.1.6:
        // 2.  Compute SHA-512(dom2(F, C) || prefix || PH(M)), where M is the
        //     message to be signed.  Interpret the 64-octet digest as a little-
        //     endian integer r.
        // @formatter:on
        MessageDigest h;
        try {
            h = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        h.update(this.prefix);
        h.update(message);
        Scalar r = Scalar.fromBytesModOrderWide(h.digest());

        // @formatter:off
        // 3.  Compute the point [r]B.  For efficiency, do this by first
        //     reducing r modulo L, the group order of B.  Let the string R be
        //     the encoding of this point.
        // @formatter:on
        CompressedEdwardsY R = Constants.ED25519_BASEPOINT_TABLE.multiply(r).compress();

        // @formatter:off
        // 4.  Compute SHA512(dom2(F, C) || R || A || PH(M)), and interpret the
        //     64-octet digest as a little-endian integer k.
        // @formatter:on
        h.reset();
        h.update(R.toByteArray());
        h.update(publicKey.toByteArray());
        h.update(message);
        Scalar k = Scalar.fromBytesModOrderWide(h.digest());

        // @formatter:off
        // 5.  Compute S = (r + k * s) mod L.  For efficiency, again reduce k
        //     modulo L first.
        // @formatter:on
        Scalar S = r.add(k.multiply(this.s));

        return new Ed25519Signature(R, S);
    }
}
