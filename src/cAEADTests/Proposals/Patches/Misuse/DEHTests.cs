namespace cAEADTests;

[TestClass]
public class DEHTests
{
    // Adapted from https://github.com/riastradh/daence/blob/master/go/chachadaence/chachadaence_test.go
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "969dda237813704a106e0907f60e00a99f9389960aca8ed89796202e4c37ecbcb0a8485e7a3aaee681bdb8b611812c3704aa00ca143a33137163bd2329cea2c4b6710a9354512ddec8a1084db190a6cbab45ca76676552f5e4",
            "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "404142434445464748494a4b4c4d4e4f"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { DEH.CommitmentSize + DEH.TagSize - 1, 0, DEH.KeySize, DEH.NonceSize };
        yield return new object[] { DEH.CommitmentSize + DEH.TagSize, 1, DEH.KeySize, DEH.NonceSize };
        yield return new object[] { DEH.CommitmentSize + DEH.TagSize, 0, DEH.KeySize + 1, DEH.NonceSize };
        yield return new object[] { DEH.CommitmentSize + DEH.TagSize, 0, DEH.KeySize - 1, DEH.NonceSize };
        yield return new object[] { DEH.CommitmentSize + DEH.TagSize, 0, DEH.KeySize, DEH.NonceSize - 1 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, DEH.KeySize);
        Assert.AreEqual(12, DEH.NonceSize);
        Assert.AreEqual(24, DEH.TagSize);
        Assert.AreEqual(32, DEH.CommitmentSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        DEH.Encrypt(c, p, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => DEH.Encrypt(c, p, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        DEH.Decrypt(p, c, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => DEH.Decrypt(p, parameters[0], parameters[1], parameters[2]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => DEH.Decrypt(p, c, k, ad));
    }
}
