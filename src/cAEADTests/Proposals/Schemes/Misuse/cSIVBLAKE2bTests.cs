namespace cAEADTests;

[TestClass]
public class cSIVBLAKE2bTests
{
    // Adapted from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#appendix-A.3.1
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "a3feb857a520d4f49e9814a874aa65e2735176aabdffe2355d859be0c31faebc83f54553c2557ca1fb098c34f318cfcbff03c08006aa86076e4d5675cc42f002e735ee9f8ebb916503b736a873269d64be5ec4df939c23e42837c4e8b0574400fd22a9532bf7667ee50f98c6fef7023c67150775b8742c09f85f9bb359e4dff625a32565a908c69c145374990f94ec0ae4e3",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "404142434445464748494a4b4c4d4e4f5051525354555657",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { cSIVBLAKE2b.TagSize - 1, 0, cSIVBLAKE2b.NonceSize, cSIVBLAKE2b.KeySize, cSIVBLAKE2b.TagSize };
        yield return new object[] { cSIVBLAKE2b.TagSize, 1, cSIVBLAKE2b.NonceSize, cSIVBLAKE2b.KeySize, cSIVBLAKE2b.TagSize };
        yield return new object[] { cSIVBLAKE2b.TagSize, 0, cSIVBLAKE2b.NonceSize + 1, cSIVBLAKE2b.KeySize, cSIVBLAKE2b.TagSize };
        yield return new object[] { cSIVBLAKE2b.TagSize, 0, cSIVBLAKE2b.NonceSize - 1, cSIVBLAKE2b.KeySize, cSIVBLAKE2b.TagSize };
        yield return new object[] { cSIVBLAKE2b.TagSize, 0, cSIVBLAKE2b.NonceSize, cSIVBLAKE2b.KeySize + 1, cSIVBLAKE2b.TagSize };
        yield return new object[] { cSIVBLAKE2b.TagSize, 0, cSIVBLAKE2b.NonceSize, cSIVBLAKE2b.KeySize - 1, cSIVBLAKE2b.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, cSIVBLAKE2b.KeySize);
        Assert.AreEqual(24, cSIVBLAKE2b.NonceSize);
        Assert.AreEqual(32, cSIVBLAKE2b.TagSize);
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

        cSIVBLAKE2b.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => cSIVBLAKE2b.Encrypt(c, p, n, k, ad));
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

        cSIVBLAKE2b.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => cSIVBLAKE2b.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => cSIVBLAKE2b.Decrypt(p, c, n, k, ad));
    }
}
