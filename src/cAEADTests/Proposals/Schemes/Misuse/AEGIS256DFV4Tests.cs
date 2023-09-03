namespace cAEADTests;

[TestClass]
public class AEGIS256DFV4Tests
{
    // Adapted from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead#appendix-A.3
    public static IEnumerable<object[]> TestVectors()
    {
        // Test Vector 1
        yield return new object[]
        {
            "856222f6856e0f003128873a16bd859261de8f87192f9cdcdbef336717ff9d503373b6a89f48251c7eb6c75e435953ecc99ed249998da8720965226e5b158493dc49ab8fcfe71206d3b6c98d0ce03bae",
            "00000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            ""
        };
        // Test Vector 2
        yield return new object[]
        {
            "1f52ca52f0e4c84315835efc91d12467d6e240eeed0c6954ed6ec590722fe5ed422d99450c0fa20d37f7eb9869fa9efde1b56ebb3dc6b791effa9c78a9125fd7",
            "",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            ""
        };
        // Test Vector 3
        yield return new object[]
        {
            "79b96813cbf8868646e91e24658334f0bafb7b9a393ace0b2530f2d322781d6c9f72648d9967e158465038ebfd2190582c95d9403e6e1dfb356c222c1967fc298a3fd5b8a696c53dbfb95d3a8b983c86280908dadcb0f8aec9c359b406c7bbe3",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607"
        };
        // Test Vector 4
        yield return new object[]
        {
            "842009de11dedbd65c91f110533b899a6ed134f27b66c582c8c0ac8506b8e190e464821c99b60b6d86c442f3eda2447dce54830e139ecfb94974337247ec563511b17bc9d9a5d9f2f61c162ec188",
            "000102030405060708090a0b0c0d",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "0001020304050607"
        };
        // Test Vector 5
        yield return new object[]
        {
            "c4c74f46a561dc0f1199c56272b729b0e63b992e4280184f6549b15d48accaf81146b5994467b631a2fe577bb2de504cc840981940b7c0ce4a2c457814314e64bbef33701843dca9102b5f8d771b05513129519c0eb9fbfaa8c729d29668c1b63d7da413676b4a0b",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "1001000000000000000000000000000000000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { AEGIS256DFV4.TagSize, 1, AEGIS256DFV4.NonceSize, AEGIS256DFV4.KeySize, 16 };
        yield return new object[] { AEGIS256DFV4.TagSize, 0, AEGIS256DFV4.NonceSize + 1, AEGIS256DFV4.KeySize, 16 };
        yield return new object[] { AEGIS256DFV4.TagSize, 0, AEGIS256DFV4.NonceSize - 1, AEGIS256DFV4.KeySize, 16 };
        yield return new object[] { AEGIS256DFV4.TagSize, 0, AEGIS256DFV4.NonceSize, AEGIS256DFV4.KeySize + 1, 16 };
        yield return new object[] { AEGIS256DFV4.TagSize, 0, AEGIS256DFV4.NonceSize, AEGIS256DFV4.KeySize - 1, 16 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, AEGIS256DFV4.KeySize);
        Assert.AreEqual(32, AEGIS256DFV4.NonceSize);
        Assert.AreEqual(64, AEGIS256DFV4.TagSize);
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

        AEGIS256DFV4.Encrypt(c, p, n, k, ad);

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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AEGIS256DFV4.Encrypt(c, p, n, k, ad));
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

        AEGIS256DFV4.Decrypt(p, c, n, k, ad);

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
            Assert.ThrowsException<CryptographicException>(() => AEGIS256DFV4.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3]));
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

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => AEGIS256DFV4.Decrypt(p, c, n, k, ad));
    }
}
