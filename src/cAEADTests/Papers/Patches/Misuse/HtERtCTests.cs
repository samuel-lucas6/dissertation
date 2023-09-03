namespace cAEADTests;

[TestClass]
public class HtERtCTests
{
    // Adapted from https://github.com/riastradh/daence/blob/master/go/chachadaence/chachadaence_test.go
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "2ef206260b5ee946354b03caafb0afbf51ca143e41960b3a8b1be61a63c4765ff394f597bfb87e1b7dd258e9f8ff57c88f71b0e5f9d3cf0eab6330173e247a83bd142954b665c2d7ee",
            "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "404142434445464748494a4b4c4d4e4f"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { HtERtC.CommitmentSize + HtERtC.TagSize - 1, 0, HtERtC.KeySize, HtERtC.NonceSize };
        yield return new object[] { HtERtC.CommitmentSize + HtERtC.TagSize, 1, HtERtC.KeySize, HtERtC.NonceSize };
        yield return new object[] { HtERtC.CommitmentSize + HtERtC.TagSize, 0, HtERtC.KeySize + 1, HtERtC.NonceSize };
        yield return new object[] { HtERtC.CommitmentSize + HtERtC.TagSize, 0, HtERtC.KeySize - 1, HtERtC.NonceSize };
        yield return new object[] { HtERtC.CommitmentSize + HtERtC.TagSize, 0, HtERtC.KeySize, HtERtC.NonceSize - 1 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, HtERtC.KeySize);
        Assert.AreEqual(12, HtERtC.NonceSize);
        Assert.AreEqual(24, HtERtC.TagSize);
        Assert.AreEqual(16, HtERtC.CommitmentSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        HtERtC.Encrypt(c, p, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HtERtC.Encrypt(c, p, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        HtERtC.Decrypt(p, c, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => HtERtC.Decrypt(p, parameters[0], parameters[1], parameters[2]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => HtERtC.Decrypt(p, c, k, ad));
    }
}
