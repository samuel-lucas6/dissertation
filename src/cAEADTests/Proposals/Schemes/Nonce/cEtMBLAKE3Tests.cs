namespace cAEADTests;

[TestClass]
public class cEtMBLAKE3Tests
{
    // Adapted from https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "16ab18368b3cacd224e5ca726c9e65c47774c77e48ec967bb684f5f8e15198ac496313c9f09bb3140bfa19bdadc3a4f3053d7a908fa5fcc4de3d17882d23712669f09696bebc670c1db5b429567cac09bac6c9a7818e242a4a33074e048a800f06ff91e385eb4c5caa9f5c4b4612f961167e782b1d78ab4e3168ac51accd0def415b37fbceec8efabcafd3a7f1ee14080a9a",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { cEtMBLAKE3.TagSize - 1, 0, cEtMBLAKE3.NonceSize, cEtMBLAKE3.KeySize, cEtMBLAKE3.TagSize };
        yield return new object[] { cEtMBLAKE3.TagSize, 1, cEtMBLAKE3.NonceSize, cEtMBLAKE3.KeySize, cEtMBLAKE3.TagSize };
        yield return new object[] { cEtMBLAKE3.TagSize, 0, cEtMBLAKE3.NonceSize + 1, cEtMBLAKE3.KeySize, cEtMBLAKE3.TagSize };
        yield return new object[] { cEtMBLAKE3.TagSize, 0, cEtMBLAKE3.NonceSize - 1, cEtMBLAKE3.KeySize, cEtMBLAKE3.TagSize };
        yield return new object[] { cEtMBLAKE3.TagSize, 0, cEtMBLAKE3.NonceSize, cEtMBLAKE3.KeySize + 1, cEtMBLAKE3.TagSize };
        yield return new object[] { cEtMBLAKE3.TagSize, 0, cEtMBLAKE3.NonceSize, cEtMBLAKE3.KeySize - 1, cEtMBLAKE3.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, cEtMBLAKE3.KeySize);
        Assert.AreEqual(12, cEtMBLAKE3.NonceSize);
        Assert.AreEqual(32, cEtMBLAKE3.TagSize);
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

        cEtMBLAKE3.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => cEtMBLAKE3.Encrypt(c, p, n, k, ad));
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

        cEtMBLAKE3.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => cEtMBLAKE3.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => cEtMBLAKE3.Decrypt(p, c, n, k, ad));
    }
}
