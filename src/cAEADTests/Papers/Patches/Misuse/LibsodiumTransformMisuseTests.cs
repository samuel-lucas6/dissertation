namespace cAEADTests;

[TestClass]
public class LibsodiumTransformMisuseTests
{
    // Adapted from https://github.com/riastradh/daence/blob/master/go/chachadaence/chachadaence_test.go
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "ac54743c1aa8ddb85995bdbe867add0e676b6d4ff8bb91380de1842b2133cd369976709c453c8f94e492efa770e3c221e08ea6a0e588d54e227d2c0cdee408bce9d0532a3a3627010f11f2b2e47267e533e95aa3b2e71efb68",
            "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f70",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "404142434445464748494a4b4c4d4e4f"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { LibsodiumTransformMisuse.CommitmentSize + LibsodiumTransformMisuse.TagSize - 1, 0, LibsodiumTransformMisuse.KeySize, LibsodiumTransformMisuse.NonceSize };
        yield return new object[] { LibsodiumTransformMisuse.CommitmentSize + LibsodiumTransformMisuse.TagSize, 1, LibsodiumTransformMisuse.KeySize, LibsodiumTransformMisuse.NonceSize };
        yield return new object[] { LibsodiumTransformMisuse.CommitmentSize + LibsodiumTransformMisuse.TagSize, 0, LibsodiumTransformMisuse.KeySize + 1, LibsodiumTransformMisuse.NonceSize };
        yield return new object[] { LibsodiumTransformMisuse.CommitmentSize + LibsodiumTransformMisuse.TagSize, 0, LibsodiumTransformMisuse.KeySize - 1, LibsodiumTransformMisuse.NonceSize };
        yield return new object[] { LibsodiumTransformMisuse.CommitmentSize + LibsodiumTransformMisuse.TagSize, 0, LibsodiumTransformMisuse.KeySize, LibsodiumTransformMisuse.NonceSize - 1 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(64, LibsodiumTransformMisuse.KeySize);
        Assert.AreEqual(12, LibsodiumTransformMisuse.NonceSize);
        Assert.AreEqual(24, LibsodiumTransformMisuse.TagSize);
        Assert.AreEqual(32, LibsodiumTransformMisuse.CommitmentSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string key, string associatedData)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        LibsodiumTransformMisuse.Encrypt(c, p, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => LibsodiumTransformMisuse.Encrypt(c, p, k, ad));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string key, string associatedData)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        LibsodiumTransformMisuse.Decrypt(p, c, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => LibsodiumTransformMisuse.Decrypt(p, parameters[0], parameters[1], parameters[2]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => LibsodiumTransformMisuse.Decrypt(p, c, k, ad));
    }
}
