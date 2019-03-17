/*
 * This file is part of ed25519-elisabeth.
 * Copyright (c) 2019 Jack Grigg
 * See LICENSE for licensing information.
 */

package cafe.cryptography.ed25519;

import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 2, timeUnit = TimeUnit.SECONDS)
@Fork(1)
@State(Scope.Benchmark)
public class Ed25519Bench {
    public SecureRandom r;
    public Ed25519PrivateKey sk;
    public Ed25519ExpandedPrivateKey expsk;
    public Ed25519PublicKey vk;
    public byte[] message;
    public Ed25519Signature signature;

    @Setup
    public void prepare() {
        this.r = new SecureRandom();
        this.sk = Ed25519PrivateKey.generate(this.r);
        this.expsk = this.sk.expand();
        this.vk = this.sk.derivePublic();
        this.message = new byte[64];
        r.nextBytes(this.message);
        this.signature = this.sk.expand().sign(this.message, this.vk);
    }

    @Benchmark
    public Ed25519PublicKey keygen() {
        return Ed25519PrivateKey.generate(this.r).derivePublic();
    }

    @Benchmark
    public Ed25519ExpandedPrivateKey expand() {
        return this.sk.expand();
    }

    @Benchmark
    public Ed25519Signature sign() {
        return this.expsk.sign(this.message, this.vk);
    }

    @Benchmark
    public boolean verify() {
        return this.vk.verify(this.message, this.signature);
    }
}
