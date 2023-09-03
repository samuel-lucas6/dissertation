namespace cAEADTests;

[TestClass]
public class ChaChaMAC256Tests
{
    // Adapted from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#section-2.2.1
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "7d15dc0c2a1e5dce0c98a2a4a4584c049e6951f991ba85169d5bc5446ee7e2f7",
            "000000090000004a0000000031415927",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
        yield return new object[]
        {
            "032b32640a81062c6ad7d30d49b4dd8878207ae3af0b4ba907459cefb1e55989",
            "000000090000004a0000000031415927000000090000004a0000000031415927",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
        yield return new object[]
        {
            "3ffebd4cda42ee8e517f81557cd4811fff0095c2b6d329c6e2fbe7d1ced427a0",
            "000000090000004a0000000031415927000000090000004a0000000031415927000000090000004a0000000031415927",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { ChaChaMAC256.TagSize + 1, 0, ChaChaMAC256.KeySize };
        yield return new object[] { ChaChaMAC256.TagSize - 1, 0, ChaChaMAC256.KeySize };
        yield return new object[] { ChaChaMAC256.TagSize, 0, ChaChaMAC256.KeySize + 1 };
        yield return new object[] { ChaChaMAC256.TagSize, 0, ChaChaMAC256.KeySize - 1 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, ChaChaMAC256.KeySize);
        Assert.AreEqual(32, ChaChaMAC256.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void ComputeTag_Valid(string tag, string message, string key)
    {
        Span<byte> t = stackalloc byte[tag.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        ChaChaMAC256.ComputeTag(t, m, k);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void ComputeTag_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaChaMAC256.ComputeTag(t, m, k));
    }
}
