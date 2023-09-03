namespace cAEADTests;

[TestClass]
public class ChaChaMAC128Tests
{
    // Adapted from https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#section-2.2.1
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "50fbb70c60cb1567c040ac65a4d22dacd6ad0df4ffa37bd73ffbad2089cf831b",
            "000000090000004a0000000031415927",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
        yield return new object[]
        {
            "c18e3464f8de60d6325b56e6900e8ebf48b266a5c6373da308c8ad8924a8583a",
            "000000090000004a0000000031415927000000090000004a0000000031415927",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
        yield return new object[]
        {
            "9f4335c0f8eb1af41698cd2f84842ec2d4675eb58878e98daaddcd09cb46b23e",
            "000000090000004a0000000031415927000000090000004a0000000031415927000000090000004a0000000031415927",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { ChaChaMAC128.TagSize + 1, 0, ChaChaMAC128.KeySize };
        yield return new object[] { ChaChaMAC128.TagSize - 1, 0, ChaChaMAC128.KeySize };
        yield return new object[] { ChaChaMAC128.TagSize, 0, ChaChaMAC128.KeySize + 1 };
        yield return new object[] { ChaChaMAC128.TagSize, 0, ChaChaMAC128.KeySize - 1 };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, ChaChaMAC128.KeySize);
        Assert.AreEqual(32, ChaChaMAC128.TagSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void ComputeTag_Valid(string tag, string message, string key)
    {
        Span<byte> t = stackalloc byte[tag.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        ChaChaMAC128.ComputeTag(t, m, k);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void ComputeTag_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ChaChaMAC128.ComputeTag(t, m, k));
    }
}
