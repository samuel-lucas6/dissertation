namespace cAEADTests;

[TestClass]
public class CommitKeyTests
{
    // Adapted from https://datatracker.ietf.org/doc/html/rfc8439#section-2.8.2
    public static IEnumerable<object[]> TestVectors()
    {
        yield return new object[]
        {
            "9b131deac9ee0f25ee19c7d4120e4d57d30fbd8b3202f4cf5a0b1fa19bcbc842ed8e7c819f26d7ecfc01f820209dc0f930093a32f445c278e1dc647c0d29a0fc114aa831eb68c11cc9c6b71b0676c087f50ef6910c351b5ac818c60b2d1ddbfa22cbbf49ff011091a80660300b20c96156626d016f700b7ff17ca3a5ddde02fe31ef001d10818da5836851a5597d413da82a4dc16728404e3495b0ec6f51d2c25890",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7",
            CommitKey.Type.I
        };
        yield return new object[]
        {
            "201aaecbb7e55273e7383bd022951b8f1b1f3d5b3061d2622a6b2a56224909f8bc4a9d75ac8e447e55a62797aa8aa41f18d851d315e85d2de1d4db0c499d1e16ac680bb7711af6c0d692951d3c257d64d2506be1bf7955029843f94357d688ad4580673a43af69fa0a0c43d67e809fa1c0074f5b38ab40e2d7081f7b6ad4d3d92e8b362fc92f8725001ea81f5b7f8b257b3816ea9b0a38efcbe2352a3251226e0752",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7",
            CommitKey.Type.II
        };
        yield return new object[]
        {
            "165765b211fdf7ef098b99194d966b2be1300c53e229679bddc89857b3578aa55f72a297b57dae41edd6cf216cfe9e9518b6b6d8a5593f8af3ace0f4eb2c3077f7b34bab306924b03996fa37f76240747f1c717dbc6bc855e06771d596764fadc6c253b9bd911866d59e2f5eef5db6d04af9cd34ef18def08361a909d03b2c5a94eb30a82052001e63ad1d662c318eeab713b651943bf0b076fa3b513d9a9f967289",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7",
            CommitKey.Type.III
        };
        yield return new object[]
        {
            "8a77d1a7badd7c42c94f1739c64708c05a6fe543ef0af52b825092a98c68a8d91b356555f2d69034561da8223b10794f7fc8a92f3f34e85f07a7b0ebdfcbe07b19ae779de337c00de47dde9ec051151b26ff08c4e2a2150ba25fad8e3952834effb628d65d209985447aabe60799c7735c08f5891626c0a64ed43f6448f6169b098c02bd699dca1b040907dc917c71b1795243a013448afb8b10387916eb98420123",
            "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
            "070000004041424344454647",
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
            "50515253c0c1c2c3c4c5c6c7",
            CommitKey.Type.IV
        };
    }

    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { CommitKey.CommitmentSize + CommitKey.TagSize - 1, 0, CommitKey.NonceSize, CommitKey.KeySize, CommitKey.TagSize, CommitKey.Type.IV };
        yield return new object[] { CommitKey.CommitmentSize + CommitKey.TagSize, 1, CommitKey.NonceSize, CommitKey.KeySize, CommitKey.TagSize, CommitKey.Type.IV };
        yield return new object[] { CommitKey.CommitmentSize + CommitKey.TagSize, 0, CommitKey.NonceSize + 1, CommitKey.KeySize, CommitKey.TagSize, CommitKey.Type.IV };
        yield return new object[] { CommitKey.CommitmentSize + CommitKey.TagSize, 0, CommitKey.NonceSize - 1, CommitKey.KeySize, CommitKey.TagSize, CommitKey.Type.IV };
        yield return new object[] { CommitKey.CommitmentSize + CommitKey.TagSize, 0, CommitKey.NonceSize, CommitKey.KeySize + 1, CommitKey.TagSize, CommitKey.Type.IV };
        yield return new object[] { CommitKey.CommitmentSize + CommitKey.TagSize, 0, CommitKey.NonceSize, CommitKey.KeySize - 1, CommitKey.TagSize, CommitKey.Type.IV };
    }

    [TestMethod]
    public void Constants_Valid()
    {
        Assert.AreEqual(32, CommitKey.KeySize);
        Assert.AreEqual(12, CommitKey.NonceSize);
        Assert.AreEqual(16, CommitKey.TagSize);
        Assert.AreEqual(32, CommitKey.CommitmentSize);
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData, CommitKey.Type type)
    {
        Span<byte> c = stackalloc byte[ciphertext.Length / 2];
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        CommitKey.Encrypt(c, p, n, k, ad, type);

        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize, CommitKey.Type type)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CommitKey.Encrypt(c, p, n, k, ad, type));
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData, CommitKey.Type type)
    {
        Span<byte> p = stackalloc byte[plaintext.Length / 2];
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> ad = Convert.FromHexString(associatedData);

        CommitKey.Decrypt(p, c, n, k, ad, type);

        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }

    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData, CommitKey.Type type)
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
            Assert.ThrowsException<CryptographicException>(() => CommitKey.Decrypt(p, parameters[0], parameters[1], parameters[2], parameters[3], type));
            param[0]--;
        }
        Assert.IsTrue(p.SequenceEqual(new byte[p.Length]));
    }

    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize, CommitKey.Type type)
    {
        var p = new byte[plaintextSize];
        var c = new byte[ciphertextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var ad = new byte[associatedDataSize];

        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CommitKey.Decrypt(p, c, n, k, ad, type));
    }
}
