namespace cAEADTests;

[TestClass]
public class cSIVBLAKE3Tests
{
    // Adapted from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#appendix-A.3.1
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "03c855c1253b3e591fcd489352f6a21e2e9a410560b53a1c26b87878f46b9172a5722105063a075bfc6ba06c4594fc9718f95b43b346a69c9fb330c5552e99c6f81f0f47c3d82bf9c6007497f8410f1f10176dac4db8a3274dbe8aebd1f37923a2d587c07de8dc78ff523bd62f8c44ed072429b8b9111b93741277fa43ed9acca1ba15969870b3f67c1796ae92ab6da91b0f",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "404142434445464748494a4b4c4d4e4f5051525354555657",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { cSIVBLAKE3.TagSize - 1, 0, cSIVBLAKE3.NonceSize, cSIVBLAKE3.KeySize, cSIVBLAKE3.TagSize };
        yield return new object[] { cSIVBLAKE3.TagSize, 1, cSIVBLAKE3.NonceSize, cSIVBLAKE3.KeySize, cSIVBLAKE3.TagSize };
        yield return new object[] { cSIVBLAKE3.TagSize, 0, cSIVBLAKE3.NonceSize + 1, cSIVBLAKE3.KeySize, cSIVBLAKE3.TagSize };
        yield return new object[] { cSIVBLAKE3.TagSize, 0, cSIVBLAKE3.NonceSize - 1, cSIVBLAKE3.KeySize, cSIVBLAKE3.TagSize };
        yield return new object[] { cSIVBLAKE3.TagSize, 0, cSIVBLAKE3.NonceSize, cSIVBLAKE3.KeySize + 1, cSIVBLAKE3.TagSize };
        yield return new object[] { cSIVBLAKE3.TagSize, 0, cSIVBLAKE3.NonceSize, cSIVBLAKE3.KeySize - 1, cSIVBLAKE3.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, cSIVBLAKE3.KeySize);
        Assert.AreEqual(24, cSIVBLAKE3.NonceSize);
        Assert.AreEqual(32, cSIVBLAKE3.TagSize);
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

        cSIVBLAKE3.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => cSIVBLAKE3.Encrypt(c, p, n, k, ad));
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

        cSIVBLAKE3.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => cSIVBLAKE3.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => cSIVBLAKE3.Decrypt(p, c, n, k, ad));
    }
}
