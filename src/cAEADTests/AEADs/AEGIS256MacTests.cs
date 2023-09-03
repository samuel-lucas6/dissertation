namespace cAEADTests;

[TestClass]
public class AEGIS256MacTests
{
    // Based on https://github.com/jedisct1/zig/blob/master/lib/std/crypto/aegis.zig
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "0f5915b53f1f490ca9fe91c3c5ef9ee37541a259ffb1c09fd82e322fad5d749e",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "0000000000000000000000000000000000000000000000000000000000000000"
        };
        yield return new object[]
        {
            "7a18b7ecc0ae899371d0a3ec68b2ea7d",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
            "0000000000000000000000000000000000000000000000000000000000000000"
        };
        yield return new object[]
        {
            "1ba95c264f1fc042b70b2256744b1b02badf6f13bfa864eb1ab6300850f7155c",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "0000000000000000000000000000000000000000000000000000000000000000"
        };
        yield return new object[]
        {
            "a1763335f0b7a4a9adbd125e24bc0e5e",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "0000000000000000000000000000000000000000000000000000000000000000"
        };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, AEGIS256Mac.KeySize);
        Assert.AreEqual(32, AEGIS256Mac.MaxTagSize);
        Assert.AreEqual(16, AEGIS256Mac.MinTagSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void ComputeTag_Valid(string tag, string message, string key)
    {
        Span<byte> t = stackalloc byte[tag.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        using var aegis = new AEGIS256Mac(k);
        aegis.Update(m);
        aegis.Finalize(t);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Incremental_Valid(string tag, string message, string key)
    {
        Span<byte> t = stackalloc byte[tag.Length / 2];
        Span<byte> m = Convert.FromHexString(message);
        Span<byte> k = Convert.FromHexString(key);

        using var aegis = new AEGIS256Mac(k);
        if (m.Length > 1) {
            aegis.Update(m[..(m.Length / 2)]);
            aegis.Update(m[(m.Length / 2)..]);
        }
        else {
            aegis.Update(m);
        }
        aegis.Update(ReadOnlySpan<byte>.Empty);
        aegis.Finalize(t);

        Assert.AreEqual(tag, Convert.ToHexString(t).ToLower());
    }

    [TestMethod]
    [DataRow(AEGIS256Mac.MaxTagSize + 1, 1, AEGIS256Mac.KeySize)]
    [DataRow(AEGIS256Mac.MaxTagSize - 1, 1, AEGIS256Mac.KeySize)]
    [DataRow(AEGIS256Mac.MinTagSize + 1, 1, AEGIS256Mac.KeySize)]
    [DataRow(AEGIS256Mac.MinTagSize - 1, 1, AEGIS256Mac.KeySize)]
    [DataRow(AEGIS256Mac.MaxTagSize, 1, AEGIS256Mac.KeySize + 1)]
    [DataRow(AEGIS256Mac.MaxTagSize, 1, AEGIS256Mac.KeySize - 1)]
    public void ComputeTag_Invalid(int tagSize, int messageSize, int keySize)
    {
        var t = new byte[tagSize];
        var m = new byte[messageSize];
        var k = new byte[keySize];

        if (keySize != AEGIS256Mac.KeySize) {
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => new AEGIS256Mac(k));
        }
        else {
            using var aegis = new AEGIS256Mac(k);
            aegis.Update(m);
            Assert.ThrowsException<ArgumentOutOfRangeException>(() => aegis.Finalize(t));
        }
    }
}
