namespace cAEADTests;

[TestClass]
public class CommitAllTests
{
    // Adapted from https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "578de1daf47f2a21e4e7372811739277810d468992bfa40eb713fc68d691260b19a00fe1c949fb8978ca01f491050a5929312cd84fb64ed005d33ae7fa7547769f503f1750c2b3169bf90e0d11454d9f705dea9f47f4b7e41479e469ed81522bf7705942d785074102b2de1f8630e0e3b4344d2b624aa61d94255bf07975207811d1aa9e3a841aa174297d8d74b9b872fec3680560dd9f76ff69b2052cc03dded6da",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { CommitAll.CommitmentSize + CommitAll.TagSize - 1, 0, CommitAll.NonceSize, CommitAll.KeySize, CommitAll.TagSize };
        yield return new object[] { CommitAll.CommitmentSize + CommitAll.TagSize, 1, CommitAll.NonceSize, CommitAll.KeySize, CommitAll.TagSize };
        yield return new object[] { CommitAll.CommitmentSize + CommitAll.TagSize, 0, CommitAll.NonceSize + 1, CommitAll.KeySize, CommitAll.TagSize };
        yield return new object[] { CommitAll.CommitmentSize + CommitAll.TagSize, 0, CommitAll.NonceSize - 1, CommitAll.KeySize, CommitAll.TagSize };
        yield return new object[] { CommitAll.CommitmentSize + CommitAll.TagSize, 0, CommitAll.NonceSize, CommitAll.KeySize + 1, CommitAll.TagSize };
        yield return new object[] { CommitAll.CommitmentSize + CommitAll.TagSize, 0, CommitAll.NonceSize, CommitAll.KeySize - 1, CommitAll.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, CommitAll.KeySize);
        Assert.AreEqual(12, CommitAll.NonceSize);
        Assert.AreEqual(16, CommitAll.TagSize);
        Assert.AreEqual(32, CommitAll.CommitmentSize);
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

        CommitAll.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CommitAll.Encrypt(c, p, n, k, ad));
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

        CommitAll.Decrypt(p, c, n, k, ad);

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

        foreach (var param in parameters.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => CommitAll.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CommitAll.Decrypt(p, c, n, k, ad));
    }
}
