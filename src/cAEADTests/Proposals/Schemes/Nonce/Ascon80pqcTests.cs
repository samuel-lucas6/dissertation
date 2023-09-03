namespace cAEADTests;

[TestClass]
public class Ascon80pqcTests
{
    // Adapted from https://github.com/ascon/ascon-c/blob/main/crypto_aead/Ascon80pqcv12/LWC_AEAD_KAT_160_128.txt
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "ad6eb2b0c1246f3f7223515dd285531e1fcb3eb1",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            ""
        };
        yield return new object[]
        {
            "0fa8091038f5135e201d7b08a55f048ad0cedf6b",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "00010203"
        };
        yield return new object[]
        {
            "2440d8424e42ff91750e97641357be169df2163f",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "a31e4ca95bd345c6f7701750b0217d3c58947fc8",
            "",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "000102030405060708090a0b0c0d0e0f101112131415"
        };
        yield return new object[]
        {
            "b60032658ee819175df3230be2d79a1b8d6a0262e8",
            "00",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            ""
        };
        yield return new object[]
        {
            "b6e785cfee9274c82fa3c80e1c50eb38c70f88839a537f25315f76d9de367434f4699e9a",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            ""
        };
        yield return new object[]
        {
            "b6e785cfee9274c82fa3c80e1c50eb385ea6b4de8d233b98cb25423ba29c1102deb65334874d32aae4",
            "000102030405060708090a0b0c0d0e0f1011121314",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            ""
        };
        yield return new object[]
        {
            "f4ef0aaac7c866b07398e6a532a9138ed037e617b4532644",
            "00010203",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "00010203"
        };
        yield return new object[]
        {
            "357d7906bea4c31113085213ed660a2be4ee6e4c41cd20d59cd4d153f49b90437a94d1e8",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "000102030405060708090a0b0c0d0e0f"
        };
        yield return new object[]
        {
            "6068c41ace9fc2a085466a2db828ab4fb606fbf5e830f01b81f0c479b6b95a08e026d3e58a2ab4c2f72b4db69f3744dc",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
        };
        yield return new object[]
        {
            "8caf6cd57b66579bd1047b95ee107d8f887443f0c2a5532c28667d3de0914fa1e858510d62c80ca3ef5b3b8af67f121a3ea3c105",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0f10111213",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { Ascon80pqc.TagSize - 1, 0, Ascon80pqc.NonceSize, Ascon80pqc.KeySize, Ascon80pqc.TagSize };
        yield return new object[] { Ascon80pqc.TagSize, 1, Ascon80pqc.NonceSize, Ascon80pqc.KeySize, Ascon80pqc.TagSize };
        yield return new object[] { Ascon80pqc.TagSize, 0, Ascon80pqc.NonceSize + 1, Ascon80pqc.KeySize, Ascon80pqc.TagSize };
        yield return new object[] { Ascon80pqc.TagSize, 0, Ascon80pqc.NonceSize - 1, Ascon80pqc.KeySize, Ascon80pqc.TagSize };
        yield return new object[] { Ascon80pqc.TagSize, 0, Ascon80pqc.NonceSize, Ascon80pqc.KeySize + 1, Ascon80pqc.TagSize };
        yield return new object[] { Ascon80pqc.TagSize, 0, Ascon80pqc.NonceSize, Ascon80pqc.KeySize - 1, Ascon80pqc.TagSize };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(20, Ascon80pqc.KeySize);
        Assert.AreEqual(16, Ascon80pqc.NonceSize);
        Assert.AreEqual(20, Ascon80pqc.TagSize);
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

        Ascon80pqc.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ascon80pqc.Encrypt(c, p, n, k, ad));
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

        Ascon80pqc.Decrypt(p, c, n, k, ad);

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

        foreach (var param in parameters.Where(param => param.Length != 0)) {
            param[0]++;
            Assert.ThrowsException<CryptographicException>(() => Ascon80pqc.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => Ascon80pqc.Decrypt(p, c, n, k, ad));
    }
}
