namespace cAEADTests;

[TestClass]
public class PaddingFixTests
{
    // Adapted from https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "9f7be95d01fd40ba15e28ffb36810aaec1c0883f09016ededd8ad087558203a502ffaf51c9fd7e4ad6be92489fb526841069d7009e060b6f14cce0ef72d47a2a8f91ab39623ed795d64a97a56e2f491be1ae2da0bccc678742928cd2543199a032eac2b58f0568d2e473c66582c4940261506923a84018a2d4134fdbae9a911716861a3317bebaac2a00427f3326504ab4a7c88133c5c6e8e8831438cf0497a42b0b",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { PaddingFix.TagSize - 1, 0, PaddingFix.NonceSize, PaddingFix.KeySize, PaddingFix.TagSize };
        yield return new object[] { PaddingFix.TagSize, 1, PaddingFix.NonceSize, PaddingFix.KeySize, PaddingFix.TagSize };
        yield return new object[] { PaddingFix.TagSize, 0, PaddingFix.NonceSize + 1, PaddingFix.KeySize, PaddingFix.TagSize };
        yield return new object[] { PaddingFix.TagSize, 0, PaddingFix.NonceSize - 1, PaddingFix.KeySize, PaddingFix.TagSize };
        yield return new object[] { PaddingFix.TagSize, 0, PaddingFix.NonceSize, PaddingFix.KeySize + 1, PaddingFix.TagSize };
        yield return new object[] { PaddingFix.TagSize, 0, PaddingFix.NonceSize, PaddingFix.KeySize - 1, PaddingFix.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, PaddingFix.KeySize);
        Assert.AreEqual(12, PaddingFix.NonceSize);
        Assert.AreEqual(16, PaddingFix.TagSize);
        Assert.AreEqual(32, PaddingFix.CommitmentSize);
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

        PaddingFix.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => PaddingFix.Encrypt(c, p, n, k, ad));
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

        PaddingFix.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => PaddingFix.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => PaddingFix.Decrypt(p, c, n, k, ad));
    }
}
