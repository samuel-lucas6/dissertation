namespace cAEADTests;

[TestClass]
public class RtCTests
{
    // Adapted from https://github.com/riastradh/daence/blob/master/go/chachadaence/chachadaence_test.go
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "29be1a8803e57d0f97dc450dc319bfafc69ddb8db74a298dea20472ed7b5725d717692bf6a3f0e68243b81527fea2e1e425836a23033df3a32c1c0ee8cec6a6cf944d70a96a38fbc2a",
            "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "404142434445464748494a4b4c4d4e4f"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { RtC.CommitmentSize + RtC.TagSize - 1, 0, RtC.KeySize, RtC.NonceSize };
        yield return new object[] { RtC.CommitmentSize + RtC.TagSize, 1, RtC.KeySize, RtC.NonceSize };
        yield return new object[] { RtC.CommitmentSize + RtC.TagSize, 0, RtC.KeySize + 1, RtC.NonceSize };
        yield return new object[] { RtC.CommitmentSize + RtC.TagSize, 0, RtC.KeySize - 1, RtC.NonceSize };
        yield return new object[] { RtC.CommitmentSize + RtC.TagSize, 0, RtC.KeySize, RtC.NonceSize - 1 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, RtC.KeySize);
        Assert.AreEqual(12, RtC.NonceSize);
        Assert.AreEqual(24, RtC.TagSize);
        Assert.AreEqual(16, RtC.CommitmentSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        RtC.Encrypt(c, p, k, ad);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => RtC.Encrypt(c, p, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        RtC.Decrypt(p, c, k, ad);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string key, string associatedData)
    {
        var p = new byte[plaintext.Length / 2];
        var parameters = new List<byte[]>
        {
            Convert.FromHexString(ciphertext),
            Convert.FromHexString(key),
            Convert.FromHexString(associatedData)
        };

        foreach (var param in parameters.Where(param => param.Length > 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => RtC.Decrypt(p, parameters[0], parameters[1], parameters[2]));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int keySize, int associatedDataSize)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => RtC.Decrypt(p, c, k, ad));
    }
}
