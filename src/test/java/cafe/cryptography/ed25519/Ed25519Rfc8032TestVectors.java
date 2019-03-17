package cafe.cryptography.ed25519;

import org.junit.Test;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 * Test against the RFC 8032 test vectors.
 */
public class Ed25519Rfc8032TestVectors {
    // @formatter:off
    static final Ed25519PrivateKey TEST_1_SK = Ed25519PrivateKey.fromByteArray(
        Utils.hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
    static final Ed25519PublicKey TEST_1_VK = Ed25519PublicKey.fromByteArray(
        Utils.hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
    static final byte[] TEST_1_MSG = new byte[] {};
    static final Ed25519Signature TEST_1_SIG = Ed25519Signature.fromByteArray(
        Utils.hexToBytes(
            "e5564300c360ac729086e2cc806e828a" +
            "84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46b" +
            "d25bf5f0595bbe24655141438e7a100b"));

    static final Ed25519PrivateKey TEST_2_SK = Ed25519PrivateKey.fromByteArray(
        Utils.hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
    static final Ed25519PublicKey TEST_2_VK = Ed25519PublicKey.fromByteArray(
        Utils.hexToBytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"));
    static final byte[] TEST_2_MSG = Utils.hexToBytes("72");
    static final Ed25519Signature TEST_2_SIG = Ed25519Signature.fromByteArray(
        Utils.hexToBytes(
            "92a009a9f0d4cab8720e820b5f642540" +
            "a2b27b5416503f8fb3762223ebdb69da" +
            "085ac1e43e15996e458f3613d0f11d8c" +
            "387b2eaeb4302aeeb00d291612bb0c00"));

    static final Ed25519PrivateKey TEST_3_SK = Ed25519PrivateKey.fromByteArray(
        Utils.hexToBytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"));
    static final Ed25519PublicKey TEST_3_VK = Ed25519PublicKey.fromByteArray(
        Utils.hexToBytes("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"));
    static final byte[] TEST_3_MSG = Utils.hexToBytes("af82");
    static final Ed25519Signature TEST_3_SIG = Ed25519Signature.fromByteArray(
        Utils.hexToBytes(
            "6291d657deec24024827e69c3abe01a3" +
            "0ce548a284743a445e3680d7db5ac3ac" +
            "18ff9b538d16f290ae67f760984dc659" +
            "4a7c15e9716ed28dc027beceea1ec40a"));

    static final Ed25519PrivateKey TEST_1024_SK = Ed25519PrivateKey.fromByteArray(
        Utils.hexToBytes("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"));
    static final Ed25519PublicKey TEST_1024_VK = Ed25519PublicKey.fromByteArray(
        Utils.hexToBytes("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"));
    static final byte[] TEST_1024_MSG = Utils.hexToBytes(
            "08b8b2b733424243760fe426a4b54908" +
            "632110a66c2f6591eabd3345e3e4eb98" +
            "fa6e264bf09efe12ee50f8f54e9f77b1" +
            "e355f6c50544e23fb1433ddf73be84d8" +
            "79de7c0046dc4996d9e773f4bc9efe57" +
            "38829adb26c81b37c93a1b270b20329d" +
            "658675fc6ea534e0810a4432826bf58c" +
            "941efb65d57a338bbd2e26640f89ffbc" +
            "1a858efcb8550ee3a5e1998bd177e93a" +
            "7363c344fe6b199ee5d02e82d522c4fe" +
            "ba15452f80288a821a579116ec6dad2b" +
            "3b310da903401aa62100ab5d1a36553e" +
            "06203b33890cc9b832f79ef80560ccb9" +
            "a39ce767967ed628c6ad573cb116dbef" +
            "efd75499da96bd68a8a97b928a8bbc10" +
            "3b6621fcde2beca1231d206be6cd9ec7" +
            "aff6f6c94fcd7204ed3455c68c83f4a4" +
            "1da4af2b74ef5c53f1d8ac70bdcb7ed1" +
            "85ce81bd84359d44254d95629e9855a9" +
            "4a7c1958d1f8ada5d0532ed8a5aa3fb2" +
            "d17ba70eb6248e594e1a2297acbbb39d" +
            "502f1a8c6eb6f1ce22b3de1a1f40cc24" +
            "554119a831a9aad6079cad88425de6bd" +
            "e1a9187ebb6092cf67bf2b13fd65f270" +
            "88d78b7e883c8759d2c4f5c65adb7553" +
            "878ad575f9fad878e80a0c9ba63bcbcc" +
            "2732e69485bbc9c90bfbd62481d9089b" +
            "eccf80cfe2df16a2cf65bd92dd597b07" +
            "07e0917af48bbb75fed413d238f5555a" +
            "7a569d80c3414a8d0859dc65a46128ba" +
            "b27af87a71314f318c782b23ebfe808b" +
            "82b0ce26401d2e22f04d83d1255dc51a" +
            "ddd3b75a2b1ae0784504df543af8969b" +
            "e3ea7082ff7fc9888c144da2af58429e" +
            "c96031dbcad3dad9af0dcbaaaf268cb8" +
            "fcffead94f3c7ca495e056a9b47acdb7" +
            "51fb73e666c6c655ade8297297d07ad1" +
            "ba5e43f1bca32301651339e22904cc8c" +
            "42f58c30c04aafdb038dda0847dd988d" +
            "cda6f3bfd15c4b4c4525004aa06eeff8" +
            "ca61783aacec57fb3d1f92b0fe2fd1a8" +
            "5f6724517b65e614ad6808d6f6ee34df" +
            "f7310fdc82aebfd904b01e1dc54b2927" +
            "094b2db68d6f903b68401adebf5a7e08" +
            "d78ff4ef5d63653a65040cf9bfd4aca7" +
            "984a74d37145986780fc0b16ac451649" +
            "de6188a7dbdf191f64b5fc5e2ab47b57" +
            "f7f7276cd419c17a3ca8e1b939ae49e4" +
            "88acba6b965610b5480109c8b17b80e1" +
            "b7b750dfc7598d5d5011fd2dcc5600a3" +
            "2ef5b52a1ecc820e308aa342721aac09" +
            "43bf6686b64b2579376504ccc493d97e" +
            "6aed3fb0f9cd71a43dd497f01f17c0e2" +
            "cb3797aa2a2f256656168e6c496afc5f" +
            "b93246f6b1116398a346f1a641f3b041" +
            "e989f7914f90cc2c7fff357876e506b5" +
            "0d334ba77c225bc307ba537152f3f161" +
            "0e4eafe595f6d9d90d11faa933a15ef1" +
            "369546868a7f3a45a96768d40fd9d034" +
            "12c091c6315cf4fde7cb68606937380d" +
            "b2eaaa707b4c4185c32eddcdd306705e" +
            "4dc1ffc872eeee475a64dfac86aba41c" +
            "0618983f8741c5ef68d3a101e8a3b8ca" +
            "c60c905c15fc910840b94c00a0b9d0");
    static final Ed25519Signature TEST_1024_SIG = Ed25519Signature.fromByteArray(
        Utils.hexToBytes(
            "0aab4c900501b3e24d7cdf4663326a3a" +
            "87df5e4843b2cbdb67cbf6e460fec350" +
            "aa5371b1508f9f4528ecea23c436d94b" +
            "5e8fcd4f681e30a6ac00a9704a188a03"));

    static final Ed25519PrivateKey TEST_SHA_SK = Ed25519PrivateKey.fromByteArray(
        Utils.hexToBytes("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"));
    static final Ed25519PublicKey TEST_SHA_VK = Ed25519PublicKey.fromByteArray(
        Utils.hexToBytes("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"));
    static final byte[] TEST_SHA_MSG = Utils.hexToBytes(
            "ddaf35a193617abacc417349ae204131" +
            "12e6fa4e89a97ea20a9eeee64b55d39a" +
            "2192992a274fc1a836ba3c23a3feebbd" +
            "454d4423643ce80e2a9ac94fa54ca49f");
    static final Ed25519Signature TEST_SHA_SIG = Ed25519Signature.fromByteArray(
        Utils.hexToBytes(
            "dc2a4459e7369633a52b1bf277839a00" +
            "201009a3efbf3ecb69bea2186c26b589" +
            "09351fc9ac90b3ecfdfbc7c66431e030" +
            "3dca179c138ac17ad9bef1177331a704"));
    // @formatter:on

    @Test
    public void testSign() {
        assertThat(TEST_1_SK.expand().sign(TEST_1_MSG, TEST_1_VK), is(TEST_1_SIG));
        assertThat(TEST_2_SK.expand().sign(TEST_2_MSG, TEST_2_VK), is(TEST_2_SIG));
        assertThat(TEST_3_SK.expand().sign(TEST_3_MSG, TEST_3_VK), is(TEST_3_SIG));
        assertThat(TEST_1024_SK.expand().sign(TEST_1024_MSG, TEST_1024_VK), is(TEST_1024_SIG));
        assertThat(TEST_SHA_SK.expand().sign(TEST_SHA_MSG, TEST_SHA_VK), is(TEST_SHA_SIG));
    }

    @Test
    public void testVerify() {
        assertTrue(TEST_1_VK.verify(TEST_1_MSG, TEST_1_SIG));
        assertTrue(TEST_2_VK.verify(TEST_2_MSG, TEST_2_SIG));
        assertTrue(TEST_3_VK.verify(TEST_3_MSG, TEST_3_SIG));
        assertTrue(TEST_1024_VK.verify(TEST_1024_MSG, TEST_1024_SIG));
        assertTrue(TEST_SHA_VK.verify(TEST_SHA_MSG, TEST_SHA_SIG));
    }
}
