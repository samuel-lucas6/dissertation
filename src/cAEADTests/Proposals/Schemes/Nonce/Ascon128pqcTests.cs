namespace cAEADTests;

[TestClass]
public class Ascon128pqcTests
{
    // Adapted from https://github.com/ascon/ascon-c/blob/main/crypto_aead/ascon128v12/LWC_AEAD_KAT_128_128.txt
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "572802f368cdfdb0a39a7299b86890c812d7e85a6dc1594b4810f3f484fd9515",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            ""
        };
        yield return new object[]
        {
            "3166855cead588c302cf8d74328f1c033b4b19431053e2c8c420c5bd4cc3b6fa",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a"
        };
        yield return new object[]
        {
            "31a0398a4f565927c5709ec1a44696b4397f2b54f0fc6f16e9be10a1bfb38037",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "47f30345a661ae335a33c14f63a9295860e55925a30016c08ad066c70499a572",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213141516"
        };
        yield return new object[]
        {
            "3d6cdf97dc7cf653a314695de73d0eb94c84cb24f21963b4aa936cce7d4deb6df2",
            "00",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            ""
        };
        yield return new object[]
        {
            "3d6c851cf842c099ce7f81796723449597b65c72a6c219c8f5262823588d8f42982f903e09c09b9577957d2f822e18e0",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            ""
        };
        yield return new object[]
        {
            "3d6c851cf842c099ce7f817967234495fd4fe46ffb04a99780348fdd3b0c02cd7801f4edbc5a92f4c65925488c54a9d9e7d8a0c999",
            "000102030405060708090a0b0c0d0e0f1011121314",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            ""
        };
        yield return new object[]
        {
            "e2a90b992b9399751c50bfcb7eaffb0e61e1167eaacfa88ee8fef5eb92dfd7c2bbda8095",
            "00010203",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            "00010203"
        };
        yield return new object[]
        {
            "51c1f45cb85c310c764b8ffef05c650a00901ac13f2dc4ca2ac41e227913ec0ce51eb577e751fd1d8b9c042547e0d439",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "85ce5894f6c2441e63096fe3f527a4079c4da7341446b1da331784e27264d0833dbcfbd435fd1a45af7e2caa8fec54b4f1001cdbd55cf6951c7159cd",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213141516171819"
        };
        yield return new object[]
        {
            "1fa40b9fd57970ecf91ccd35b13d3bfd9fb87f5317ccc20e91272f9ae83da0f5849d05844d934163f63ab2646dbfc9d66b9bcc4fcc2b3ab5f279e2b1a0021df2",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { Ascon128pqc.TagSize - 1, 0, Ascon128pqc.NonceSize, Ascon128pqc.KeySize, Ascon128pqc.TagSize };
        yield return new object[] { Ascon128pqc.TagSize, 1, Ascon128pqc.NonceSize, Ascon128pqc.KeySize, Ascon128pqc.TagSize };
        yield return new object[] { Ascon128pqc.TagSize, 0, Ascon128pqc.NonceSize + 1, Ascon128pqc.KeySize, Ascon128pqc.TagSize };
        yield return new object[] { Ascon128pqc.TagSize, 0, Ascon128pqc.NonceSize - 1, Ascon128pqc.KeySize, Ascon128pqc.TagSize };
        yield return new object[] { Ascon128pqc.TagSize, 0, Ascon128pqc.NonceSize, Ascon128pqc.KeySize + 1, Ascon128pqc.TagSize };
        yield return new object[] { Ascon128pqc.TagSize, 0, Ascon128pqc.NonceSize, Ascon128pqc.KeySize - 1, Ascon128pqc.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, Ascon128pqc.KeySize);
        Assert.AreEqual(16, Ascon128pqc.NonceSize);
        Assert.AreEqual(32, Ascon128pqc.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        Ascon128pqc.Encrypt(c, p, n, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ascon128pqc.Encrypt(c, p, n, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        Ascon128pqc.Decrypt(p, c, n, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(nonce),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };

        foreach (var param in parameters.Where(param => param.Length != 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => Ascon128pqc.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ascon128pqc.Decrypt(p, c, n, k, ad));
    }
}
