namespace cAEADTests;

[TestClass]
public class AEGIS256SIVTests
{
    // Adapted from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead#appendix-A.3
    public static IEnumerable<object[]> TestVectors()
    {
        // Test Vector 1
        yield return new object[]
        {
            "d522db72d380e1fc2573b33ea888a2f083c90f8f982708c272440f4284c76d089006aa4c3872d50716d9094b1d2567b5",
            "00000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            ""
        };
        // Test Vector 2
        yield return new object[]
        {
            "9fbaa7bfe650ac941ca78ee2f430c88df23a9775c164159ac1a7cf2373b9d7ef",
            "",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            ""
        };
        // Test Vector 3
        yield return new object[]
        {
            "ca4b54f8cb689ec59ffa5cebd54965c46196524c523ea4d8b321864471a6c6eaa865eb65376c207abdc6ab62a66733e127d566f246042157a73fc3b67aa1f009",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607"
        };
        // Test Vector 4
        yield return new object[]
        {
            "a764514b73b288e4631037f9fa69867d9f6a08b8f6f10ed5f92d37558739c1f21e57ef6e02904917149e9f5057ec",
            "000102030405060708090a0b0c0d",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607"
        };
        // Test Vector 5
        yield return new object[]
        {
            "ccfee5d99d7212e96a3a1d0d913f0d0fa663be166dc68f9f57ba0c1e2dc35134aece483aac8e4fcf63e8babb0660bad37594ece7a58310859b687c64f63449197814abebf47b0098",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { AEGIS256SIV.TagSize, 1, AEGIS256SIV.NonceSize, AEGIS256SIV.KeySize, 16 };
        yield return new object[] { AEGIS256SIV.TagSize, 0, AEGIS256SIV.NonceSize + 1, AEGIS256SIV.KeySize, 16 };
        yield return new object[] { AEGIS256SIV.TagSize, 0, AEGIS256SIV.NonceSize - 1, AEGIS256SIV.KeySize, 16 };
        yield return new object[] { AEGIS256SIV.TagSize, 0, AEGIS256SIV.NonceSize, AEGIS256SIV.KeySize + 1, 16 };
        yield return new object[] { AEGIS256SIV.TagSize, 0, AEGIS256SIV.NonceSize, AEGIS256SIV.KeySize - 1, 16 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, AEGIS256SIV.KeySize);
        Assert.AreEqual(32, AEGIS256SIV.NonceSize);
        Assert.AreEqual(32, AEGIS256SIV.TagSize);
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

        AEGIS256SIV.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AEGIS256SIV.Encrypt(c, p, n, k, ad));
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

        AEGIS256SIV.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => AEGIS256SIV.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AEGIS256SIV.Decrypt(p, c, n, k, ad));
    }
}
