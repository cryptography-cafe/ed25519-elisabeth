/*
 * This file is part of ed25519-elisabeth.
 * Copyright (c) 2020 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.ed25519;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import org.openjdk.jmh.annotations.*;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 2, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class BCBench {
    public Ed25519KeyPairGenerator keyGenerator;
    public AsymmetricKeyParameter sk;
    public AsymmetricKeyParameter vk;
    public byte[] message;
    public byte[] signature;

    @Setup
    public void prepare() throws CryptoException {
        SecureRandom r = new SecureRandom();
        this.keyGenerator = new Ed25519KeyPairGenerator();
        this.keyGenerator.init(new Ed25519KeyGenerationParameters(r));

        AsymmetricCipherKeyPair keyPair = this.keyGenerator.generateKeyPair();
        this.sk = keyPair.getPrivate();
        this.vk = keyPair.getPublic();

        this.message = new byte[64];
        r.nextBytes(this.message);

        Signer signer = new Ed25519Signer();
        signer.init(true, this.sk);
        signer.update(this.message, 0, this.message.length);
        this.signature = signer.generateSignature();
    }

    @Benchmark
    public AsymmetricCipherKeyPair keygen() {
        return this.keyGenerator.generateKeyPair();
    }

    @Benchmark
    public byte[] sign() throws CryptoException {
        Signer signer = new Ed25519Signer();
        signer.init(true, this.sk);
        signer.update(this.message, 0, this.message.length);
        return signer.generateSignature();
    }

    @Benchmark
    public boolean verify() {
        Signer signer = new Ed25519Signer();
        signer.init(false, this.vk);
        signer.update(this.message, 0, this.message.length);
        return signer.verifySignature(this.signature);
    }
}
