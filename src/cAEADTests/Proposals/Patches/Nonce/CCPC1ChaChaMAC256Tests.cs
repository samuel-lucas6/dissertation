namespace cAEADTests;

[TestClass]
public class CCPC1ChaChaMAC256Tests
{
    // Adapted from https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116edd536a0bdcb8b33f02169734148a70b86fe1bb2e3482a2e0f42b3000cb95675",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { CCPC1ChaChaMAC256.TagSize - 1, 0, CCPC1ChaChaMAC256.NonceSize, CCPC1ChaChaMAC256.KeySize, CCPC1ChaChaMAC256.TagSize };
        yield return new object[] { CCPC1ChaChaMAC256.TagSize, 1, CCPC1ChaChaMAC256.NonceSize, CCPC1ChaChaMAC256.KeySize, CCPC1ChaChaMAC256.TagSize };
        yield return new object[] { CCPC1ChaChaMAC256.TagSize, 0, CCPC1ChaChaMAC256.NonceSize + 1, CCPC1ChaChaMAC256.KeySize, CCPC1ChaChaMAC256.TagSize };
        yield return new object[] { CCPC1ChaChaMAC256.TagSize, 0, CCPC1ChaChaMAC256.NonceSize - 1, CCPC1ChaChaMAC256.KeySize, CCPC1ChaChaMAC256.TagSize };
        yield return new object[] { CCPC1ChaChaMAC256.TagSize, 0, CCPC1ChaChaMAC256.NonceSize, CCPC1ChaChaMAC256.KeySize + 1, CCPC1ChaChaMAC256.TagSize };
        yield return new object[] { CCPC1ChaChaMAC256.TagSize, 0, CCPC1ChaChaMAC256.NonceSize, CCPC1ChaChaMAC256.KeySize - 1, CCPC1ChaChaMAC256.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, CCPC1ChaChaMAC256.KeySize);
        Assert.AreEqual(12, CCPC1ChaChaMAC256.NonceSize);
        Assert.AreEqual(32, CCPC1ChaChaMAC256.TagSize);
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

        CCPC1ChaChaMAC256.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CCPC1ChaChaMAC256.Encrypt(c, p, n, k, ad));
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

        CCPC1ChaChaMAC256.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => CCPC1ChaChaMAC256.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CCPC1ChaChaMAC256.Decrypt(p, c, n, k, ad));
    }
}
