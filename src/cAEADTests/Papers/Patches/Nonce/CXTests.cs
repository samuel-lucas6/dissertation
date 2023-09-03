namespace cAEADTests;

[TestClass]
public class CXTests
{
    // https://github.com/samuel-lucas6/UtC.NET/blob/main/src/UtCDotNetTests/CXTests.cs
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "f2b02c474458649f6a3334d944278190",
            "306c92755683e9f9b581363e19177cb0",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        };
        yield return new object[]
        {
            "f2b02c474458649f6a3334d944278190",
            "306c92755683e9f9b581363e19177cb0bab84a7130836d7a968cbbb921a2b92d",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        };
        yield return new object[]
        {
            "f2b02c474458649f6a3334d944278190306c92755683e9f9b581363e19177cb0",
            "bab84a7130836d7a968cbbb921a2b92d9de8d6351875518bc3dbcd72f120d797",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { CX.MinCommitmentSize + 1, CX.BlockSize, UtC.NonceSize, UtC.KeySize };
        yield return new object[] { CX.MinCommitmentSize - 1, CX.BlockSize, UtC.NonceSize, UtC.KeySize };
        yield return new object[] { CX.MaxCommitmentSize + 1, CX.BlockSize, UtC.NonceSize, UtC.KeySize };
        yield return new object[] { CX.MaxCommitmentSize - 1, CX.BlockSize, UtC.NonceSize, UtC.KeySize };
        yield return new object[] { CX.BlockSize, CX.MinSubkeySize + 1, UtC.NonceSize, UtC.KeySize };
        yield return new object[] { CX.BlockSize, CX.MinSubkeySize - 1, UtC.NonceSize, UtC.KeySize };
        yield return new object[] { CX.BlockSize, CX.MaxSubkeySize + 1, UtC.NonceSize, UtC.KeySize };
        yield return new object[] { CX.BlockSize, CX.MaxSubkeySize - 1, UtC.NonceSize, UtC.KeySize };
        yield return new object[] { CX.BlockSize, CX.BlockSize, CX.MaxNonceSize + 1, UtC.KeySize };
        yield return new object[] { CX.BlockSize, CX.BlockSize, CX.MaxNonceSize + 2, UtC.KeySize };
        yield return new object[] { CX.BlockSize, CX.BlockSize, UtC.NonceSize, CX.MinKeySize + 1 };
        yield return new object[] { CX.BlockSize, CX.BlockSize, UtC.NonceSize, CX.MinKeySize - 1 };
        yield return new object[] { CX.BlockSize, CX.BlockSize, UtC.NonceSize, CX.MaxKeySize + 1 };
        yield return new object[] { CX.BlockSize, CX.BlockSize, UtC.NonceSize, CX.MaxKeySize - 1 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(16, CX.BlockSize);
        Assert.AreEqual(16, CX.MinCommitmentSize);
        Assert.AreEqual(32, CX.MaxCommitmentSize);
        Assert.AreEqual(16, CX.MinSubkeySize);
        Assert.AreEqual(32, CX.MaxSubkeySize);
        Assert.AreEqual(15, CX.MaxNonceSize);
        Assert.AreEqual(16, CX.MinKeySize);
        Assert.AreEqual(32, CX.MaxKeySize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Derive_Valid(string commitment, string subkey, string nonce, string key)
    {
        Span<byte> c = stackalloc byte[commitment.Length / 2];
        Span<byte> s = stackalloc byte[subkey.Length / 2];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);

        CX.Derive(c, s, n, k);

        Assert.AreEqual(commitment, Convert.ToHexString(c).ToLower());
        Assert.AreEqual(subkey, Convert.ToHexString(s).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Derive_Invalid(int commitmentSize, int subkeySize, int nonceSize, int keySize)
    {
        var c = new byte[commitmentSize];
        var s = new byte[subkeySize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CX.Derive(c, s, n, k));
    }
}
