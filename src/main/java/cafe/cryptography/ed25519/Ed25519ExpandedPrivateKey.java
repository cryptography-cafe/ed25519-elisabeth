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
import org.jetbrains.annotations.NotNull;

/**
 * An Ed25519 expanded private key.
 */
public class Ed25519ExpandedPrivateKey {
    private final Scalar s;

    /**
     * The prefix component of the expanded Ed25519 private key.
     *
     * Note that because the `final` keyword only makes the reference a constant,
     * the contents of this byte[] could in theory be mutated (via reflection, as
     * this field is private). This misunderstanding was a contributor to the
     * "final" security bug in Google's Java implementation of Ed25519 [0]. However,
     * the primary cause of that bug was their reuse of the prefix buffer to hold
     * the result of calculating S; we are protected from that failure mode by the
     * type-safe curve25519-elisabeth API.
     *
     * [0] https://github.com/cryptosubtlety/final-security-bug
     */
    private final byte[] prefix;

    /**
     * The public key corresponding to this private key.
     *
     * We store the public key inside the expanded private key so that we always use
     * the correct public key when creating signatures, while caching its
     * computation along with the other expanded components.
     *
     * Version 0.1.0 of ed25519-elisabeth required the caller to provide the public
     * key. This allowed the caller to control how the public key was cached in
     * memory, but it created an opportunity for misuse: if two signatures were
     * created using different public keys, the private scalar could be recovered
     * from the signatures [0] [1]. We now always cache the public key ourselves to
     * provide a safer signing API.
     *
     * [0] https://github.com/jedisct1/libsodium/issues/170
     * [1] https://github.com/MystenLabs/ed25519-unsafe-libs
     */
    private final Ed25519PublicKey publicKey;

    Ed25519ExpandedPrivateKey(Scalar s, byte[] prefix) {
        this.s = s;
        this.prefix = prefix;
        EdwardsPoint A = Constants.ED25519_BASEPOINT_TABLE.multiply(this.s);
        this.publicKey = new Ed25519PublicKey(A);
    }

    /**
     * Returns the Ed25519 public key corresponding to this expanded private key.
     *
     * @return the public key.
     */
    @NotNull
    public Ed25519PublicKey derivePublic() {
        return this.publicKey;
    }

    /**
     * Sign a message with this expanded private key.
     *
     * @return the signature.
     */
    @NotNull
    public Ed25519Signature sign(@NotNull byte[] message) {
        return this.sign(message, 0, message.length);
    }

    /**
     * Sign a message with this expanded private key.
     *
     * @return the signature.
     */
    @NotNull
    public Ed25519Signature sign(@NotNull byte[] message, int offset, int length) {
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
        h.update(message, offset, length);
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
        h.update(this.publicKey.toByteArray());
        h.update(message, offset, length);
        Scalar k = Scalar.fromBytesModOrderWide(h.digest());

        // @formatter:off
        // 5.  Compute S = (r + k * s) mod L.  For efficiency, again reduce k
        //     modulo L first.
        // @formatter:on
        Scalar S = r.add(k.multiply(this.s));

        return new Ed25519Signature(R, S);
    }
}
