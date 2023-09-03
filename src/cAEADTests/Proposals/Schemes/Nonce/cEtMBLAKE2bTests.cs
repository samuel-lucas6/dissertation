namespace cAEADTests;

[TestClass]
public class cEtMBLAKE2bTests
{
    // Adapted from https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "a01cfe034c065a28c6f2718f7d7fa9220c7cda20e610f65979a23139983f08a016604394c05b71bd26ad6809b4200d1a785fb29706af04f62c156e7bf56c20d23bad12a8c354bec862c7519392040c1538342c9609ac5c8503de73e7ea6c48768f0235141ec5fd40d4b5234b53694d956b06d024565bedc388eee3a6dcbded69907d15d434108c285e84a5d43e11e1124c6a",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { cEtMBLAKE2b.TagSize - 1, 0, cEtMBLAKE2b.NonceSize, cEtMBLAKE2b.KeySize, cEtMBLAKE2b.TagSize };
        yield return new object[] { cEtMBLAKE2b.TagSize, 1, cEtMBLAKE2b.NonceSize, cEtMBLAKE2b.KeySize, cEtMBLAKE2b.TagSize };
        yield return new object[] { cEtMBLAKE2b.TagSize, 0, cEtMBLAKE2b.NonceSize + 1, cEtMBLAKE2b.KeySize, cEtMBLAKE2b.TagSize };
        yield return new object[] { cEtMBLAKE2b.TagSize, 0, cEtMBLAKE2b.NonceSize - 1, cEtMBLAKE2b.KeySize, cEtMBLAKE2b.TagSize };
        yield return new object[] { cEtMBLAKE2b.TagSize, 0, cEtMBLAKE2b.NonceSize, cEtMBLAKE2b.KeySize + 1, cEtMBLAKE2b.TagSize };
        yield return new object[] { cEtMBLAKE2b.TagSize, 0, cEtMBLAKE2b.NonceSize, cEtMBLAKE2b.KeySize - 1, cEtMBLAKE2b.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, cEtMBLAKE2b.KeySize);
        Assert.AreEqual(12, cEtMBLAKE2b.NonceSize);
        Assert.AreEqual(32, cEtMBLAKE2b.TagSize);
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

        cEtMBLAKE2b.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => cEtMBLAKE2b.Encrypt(c, p, n, k, ad));
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

        cEtMBLAKE2b.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => cEtMBLAKE2b.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => cEtMBLAKE2b.Decrypt(p, c, n, k, ad));
    }
}
