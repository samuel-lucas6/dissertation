namespace cAEADTests;

[TestClass]
public class oEtMBLAKE3Tests
{
    // Adapted from https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "37cd4f4c48c767ce67d25a12c18721e86f8cb31d301abfcb5efb10585db9328cd15ea3b88dfc748deb37d582e94263bbd3c2f8e86b241bed188407405dd14979f117907d6e93259a618bffdb50ee788eb5a8ed1f6f741aabafeffca726f76dd62decae5dc2ae2944cdb6d62f98be7281012ad1c069387ba3222620c4d7d99bb76a53fbf331ab6ae0c1ee8cd10862e979a910",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { oEtMBLAKE3.TagSize - 1, 0, oEtMBLAKE3.NonceSize, oEtMBLAKE3.KeySize, oEtMBLAKE3.TagSize };
        yield return new object[] { oEtMBLAKE3.TagSize, 1, oEtMBLAKE3.NonceSize, oEtMBLAKE3.KeySize, oEtMBLAKE3.TagSize };
        yield return new object[] { oEtMBLAKE3.TagSize, 0, oEtMBLAKE3.NonceSize + 1, oEtMBLAKE3.KeySize, oEtMBLAKE3.TagSize };
        yield return new object[] { oEtMBLAKE3.TagSize, 0, oEtMBLAKE3.NonceSize - 1, oEtMBLAKE3.KeySize, oEtMBLAKE3.TagSize };
        yield return new object[] { oEtMBLAKE3.TagSize, 0, oEtMBLAKE3.NonceSize, oEtMBLAKE3.KeySize + 1, oEtMBLAKE3.TagSize };
        yield return new object[] { oEtMBLAKE3.TagSize, 0, oEtMBLAKE3.NonceSize, oEtMBLAKE3.KeySize - 1, oEtMBLAKE3.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, oEtMBLAKE3.KeySize);
        Assert.AreEqual(12, oEtMBLAKE3.NonceSize);
        Assert.AreEqual(32, oEtMBLAKE3.TagSize);
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

        oEtMBLAKE3.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => oEtMBLAKE3.Encrypt(c, p, n, k, ad));
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

        oEtMBLAKE3.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => oEtMBLAKE3.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => oEtMBLAKE3.Decrypt(p, c, n, k, ad));
    }
}
