namespace cAEADTests;

[TestClass]
public class UtCTests
{
    // https://github.com/samuel-lucas6/UtC.NET/blob/main/src/UtCDotNetTests/UtCTests.cs
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "f2b02c474458649f6a3334d944278190475d273b62fe001c280fa36bfcd205b0d7b1ff027690e020ea55e1980953918af0e87b3b971e7f11e449f9550d30d4bb191f72e9d4bebb7bfe8069696a4e15856e5424c43d0688e36d6ca7aca74c6484e5b6c2a2ed7c16411e90cd05f23267884d530c7598af7a721805d1b7391e47c3bb9d3b788fb725a8183897b97d3ae1b8f567",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { UtC.CommitmentSize + UtC.TagSize - 1, 0, UtC.NonceSize, UtC.KeySize, UtC.TagSize };
        yield return new object[] { UtC.CommitmentSize + UtC.TagSize, 1, UtC.NonceSize, UtC.KeySize, UtC.TagSize };
        yield return new object[] { UtC.CommitmentSize + UtC.TagSize, 0, UtC.NonceSize + 1, UtC.KeySize, UtC.TagSize };
        yield return new object[] { UtC.CommitmentSize + UtC.TagSize, 0, UtC.NonceSize - 1, UtC.KeySize, UtC.TagSize };
        yield return new object[] { UtC.CommitmentSize + UtC.TagSize, 0, UtC.NonceSize, UtC.KeySize + 1, UtC.TagSize };
        yield return new object[] { UtC.CommitmentSize + UtC.TagSize, 0, UtC.NonceSize, UtC.KeySize - 1, UtC.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, UtC.KeySize);
        Assert.AreEqual(12, UtC.NonceSize);
        Assert.AreEqual(16, UtC.TagSize);
        Assert.AreEqual(16, UtC.CommitmentSize);
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

        UtC.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => UtC.Encrypt(c, p, n, k, ad));
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

        UtC.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => UtC.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => UtC.Decrypt(p, c, n, k, ad));
    }
}
