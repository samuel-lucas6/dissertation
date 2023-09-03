using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using Aes = System.Runtime.Intrinsics.X86.Aes;

namespace cAEAD;

internal static class AEGIS256SIVx86
{
    private static Vector128<byte> S0, S1, S2, S3, S4, S5;

    internal static bool IsSupported() => Aes.IsSupported;

    internal static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Span<byte> context = stackalloc byte[16];
        context.Clear();
        context[^1] = 0x01;
        Init(context, key, nonce);

        int i = 0;
        Span<byte> pad = stackalloc byte[16];
        while (i + 16 <= associatedData.Length) {
            Absorb(associatedData.Slice(i, 16));
            i += 16;
        }
        if (associatedData.Length % 16 != 0) {
            pad.Clear();
            associatedData[i..].CopyTo(pad);
            Absorb(pad);
        }

        i = 0;
        while (i + 16 <= plaintext.Length) {
            Absorb(plaintext.Slice(i, 16));
            i += 16;
        }
        if (plaintext.Length % 16 != 0) {
            pad.Clear();
            plaintext[i..].CopyTo(pad);
            Absorb(pad);
        }

        Span<byte> tag = ciphertext[^AEGIS256SIV.TagSize..];
        Finalize(tag, (ulong)associatedData.Length, (ulong)plaintext.Length);

        context[^1] = 0x02;
        Init(context, key, tag);

        i = 0;
        while (i + 16 <= plaintext.Length) {
            Enc(ciphertext.Slice(i, 16), plaintext.Slice(i, 16));
            i += 16;
        }
        if (plaintext.Length % 16 != 0) {
            Span<byte> tmp = stackalloc byte[16];
            pad.Clear();
            plaintext[i..].CopyTo(pad);
            Enc(tmp, pad);
            tmp[..(plaintext.Length % 16)].CopyTo(ciphertext[i..^tag.Length]);
        }
        CryptographicOperations.ZeroMemory(pad);
    }

    internal static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        ReadOnlySpan<byte> tag = ciphertext[^AEGIS256SIV.TagSize..];
        Span<byte> context = stackalloc byte[16];
        context.Clear();
        context[^1] = 0x02;
        Init(context, key, tag);

        int i = 0;
        Span<byte> pad = stackalloc byte[16];
        while (i + 16 <= ciphertext.Length - tag.Length) {
            Dec(plaintext.Slice(i, 16), ciphertext.Slice(i, 16));
            i += 16;
        }
        if ((ciphertext.Length - tag.Length) % 16 != 0) {
            DecPartial(plaintext[i..], ciphertext[i..^tag.Length]);
        }

        context[^1] = 0x01;
        Init(context, key, nonce);

        i = 0;
        while (i + 16 <= associatedData.Length) {
            Absorb(associatedData.Slice(i, 16));
            i += 16;
        }
        if (associatedData.Length % 16 != 0) {
            pad.Clear();
            associatedData[i..].CopyTo(pad);
            Absorb(pad);
        }

        i = 0;
        while (i + 16 <= plaintext.Length) {
            Absorb(plaintext.Slice(i, 16));
            i += 16;
        }
        if (plaintext.Length % 16 != 0) {
            pad.Clear();
            plaintext[i..].CopyTo(pad);
            Absorb(pad);
        }
        CryptographicOperations.ZeroMemory(pad);

        Span<byte> computedTag = stackalloc byte[AEGIS256SIV.TagSize];
        Finalize(computedTag, (ulong)associatedData.Length, (ulong)plaintext.Length);

        if (!CryptographicOperations.FixedTimeEquals(computedTag, tag)) {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(computedTag);
            throw new CryptographicException();
        }
    }

    private static void Init(ReadOnlySpan<byte> context, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        ReadOnlySpan<byte> c = stackalloc byte[]
        {
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
            0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
        };
        Vector128<byte> c0 = Vector128.Create(c[..16]);
        Vector128<byte> c1 = Vector128.Create(c[16..]);
        Vector128<byte> k0 = Vector128.Create(key[..16]);
        Vector128<byte> k1 = Vector128.Create(key[16..]);
        Vector128<byte> n0 = Vector128.Create(nonce[..16]);
        Vector128<byte> n1 = Vector128.Create(nonce[16..]);
        Vector128<byte> ctx = Vector128.Create(context);

        S0 = k0 ^ n0;
        S1 = k1 ^ n1;
        S2 = c1;
        S3 = c0;
        S4 = k0 ^ c0;
        S5 = k1 ^ c1;

        for (int i = 0; i < 4; i++) {
            S3 ^= ctx;
            S5 ^= ctx;
            Update(k0);
            S3 ^= ctx;
            S5 ^= ctx;
            Update(k1);
            S3 ^= ctx;
            S5 ^= ctx;
            Update(k0 ^ n0);
            S3 ^= ctx;
            S5 ^= ctx;
            Update(k1 ^ n1);
        }
    }

    private static void Update(Vector128<byte> message)
    {
        Vector128<byte> s0 = Aes.Encrypt(S5, S0 ^ message);
        Vector128<byte> s1 = Aes.Encrypt(S0, S1);
        Vector128<byte> s2 = Aes.Encrypt(S1, S2);
        Vector128<byte> s3 = Aes.Encrypt(S2, S3);
        Vector128<byte> s4 = Aes.Encrypt(S3, S4);
        Vector128<byte> s5 = Aes.Encrypt(S4, S5);

        S0 = s0;
        S1 = s1;
        S2 = s2;
        S3 = s3;
        S4 = s4;
        S5 = s5;
    }

    private static void Absorb(ReadOnlySpan<byte> associatedData)
    {
        Vector128<byte> ad = Vector128.Create(associatedData);
        Update(ad);
    }

    private static void Enc(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext)
    {
        Vector128<byte> z = S1 ^ S4 ^ S5 ^ (S2 & S3);
        Vector128<byte> xi = Vector128.Create(plaintext);
        Update(xi);
        Vector128<byte> ci = xi ^ z;
        ci.CopyTo(ciphertext);
    }

    private static void Dec(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> z = S1 ^ S4 ^ S5 ^ (S2 & S3);
        Vector128<byte> ci = Vector128.Create(ciphertext);
        Vector128<byte> xi = ci ^ z;
        Update(xi);
        xi.CopyTo(plaintext);
    }

    private static void DecPartial(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext)
    {
        Vector128<byte> z = S1 ^ S4 ^ S5 ^ (S2 & S3);

        var pad = new byte[16];
        ciphertext.CopyTo(pad);
        Vector128<byte> t = Vector128.Create(pad);
        Vector128<byte> output = t ^ z;

        Span<byte> p = pad;
        output.CopyTo(p);
        p[..ciphertext.Length].CopyTo(plaintext);

        p[ciphertext.Length..].Clear();
        Vector128<byte> v = Vector128.Create(pad);
        Update(v);
    }

    private static void Finalize(Span<byte> tag, ulong associatedDataLength, ulong plaintextLength)
    {
        var b = new byte[16]; Span<byte> bb = b;
        BinaryPrimitives.WriteUInt64LittleEndian(bb[..8], associatedDataLength * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(bb[8..], plaintextLength * 8);

        Vector128<byte> t = S3 ^ Vector128.Create(b);

        for (int i = 0; i < 7; i++) {
            Update(t);
        }

        Vector128<byte> a1 = S0 ^ S1 ^ S2;
        Vector128<byte> a2 = S3 ^ S4 ^ S5;
        a1.CopyTo(tag[..16]);
        a2.CopyTo(tag[16..]);
    }
}
