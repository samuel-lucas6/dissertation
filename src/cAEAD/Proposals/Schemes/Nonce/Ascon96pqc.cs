using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Buffers.Binary;

namespace cAEAD;

public static class Ascon96pqc
{
    public const int KeySize = 24;
    public const int NonceSize = 12;
    public const int TagSize = 24;
    private const int Rate = 8;
    private static ulong x0, x1, x2, x3, x4;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length != plaintext.Length + TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be {plaintext.Length + TagSize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        ulong k0 = BinaryPrimitives.ReadUInt32BigEndian(key[..4]);
        ulong k1 = BinaryPrimitives.ReadUInt64BigEndian(key[4..12]);
        ulong k2 = BinaryPrimitives.ReadUInt64BigEndian(key[12..20]);
        ulong k3 = BinaryPrimitives.ReadUInt64BigEndian(key[20..]);
        ulong n0 = BinaryPrimitives.ReadUInt64BigEndian(nonce[..4]);
        ulong n1 = BinaryPrimitives.ReadUInt64BigEndian(nonce[4..]);

        x0 = 0xc0400c0600000000 | k0;
        x1 = k1;
        x2 = k2;
        x3 = k3 << 32 | n0;
        x4 = n1;
        Permutation(rounds: 12);
        x2 ^= k0 << 32 | k1 >> 32;
        x3 ^= k1 << 32 | k2 >> 32;
        x4 ^= k2 << 32 | k3 << 32;

        int i = 0;
        Span<byte> padding = stackalloc byte[Rate];
        if (associatedData.Length != 0) {
            while (i + Rate <= associatedData.Length) {
                x0 ^= BinaryPrimitives.ReadUInt64BigEndian(associatedData.Slice(i, Rate));
                Permutation(rounds: 6);
                i += Rate;
            }
            padding.Clear();
            if (associatedData.Length % Rate != 0) {
                associatedData[i..].CopyTo(padding);
            }
            padding[associatedData.Length % Rate] = 0x80;
            x0 ^= BinaryPrimitives.ReadUInt64BigEndian(padding);
            Permutation(rounds: 6);
        }
        x4 ^= 1;

        i = 0;
        while (i + Rate <= plaintext.Length) {
            x0 ^= BinaryPrimitives.ReadUInt64BigEndian(plaintext.Slice(i, Rate));
            BinaryPrimitives.WriteUInt64BigEndian(ciphertext.Slice(i, Rate), x0);
            Permutation(rounds: 6);
            i += Rate;
        }
        padding.Clear();
        if (plaintext.Length % Rate != 0) {
            plaintext[i..].CopyTo(padding);
        }
        padding[plaintext.Length % Rate] = 0x80;
        x0 ^= BinaryPrimitives.ReadUInt64BigEndian(padding);
        BinaryPrimitives.WriteUInt64BigEndian(padding, x0);
        padding[..(plaintext.Length % Rate)].CopyTo(ciphertext[i..^TagSize]);

        x1 ^= k0 << 32 | k1 >> 32;
        x2 ^= k1 << 32 | k2 >> 32;
        x3 ^= k2 << 32 | k3 << 32;
        Permutation(rounds: 12);
        x2 ^= k0 << 32 | k1 >> 32;
        x3 ^= k1 << 32 | k2 >> 32;
        x4 ^= k2 << 32 | k3 << 32;
        BinaryPrimitives.WriteUInt64BigEndian(ciphertext[^TagSize..^(TagSize - 8)], x2);
        BinaryPrimitives.WriteUInt64BigEndian(ciphertext[^(TagSize - 8)..^(TagSize - 16)], x3);
        BinaryPrimitives.WriteUInt64BigEndian(ciphertext[^(TagSize - 16)..], x4);
        ZeroState();
        CryptographicOperations.ZeroMemory(padding);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        if (ciphertext.Length < TagSize) { throw new ArgumentOutOfRangeException(nameof(ciphertext), ciphertext.Length, $"{nameof(ciphertext)} must be at least {TagSize} bytes long."); }
        if (plaintext.Length != ciphertext.Length - TagSize) { throw new ArgumentOutOfRangeException(nameof(plaintext), plaintext.Length, $"{nameof(plaintext)} must be {ciphertext.Length - TagSize} bytes long."); }
        if (nonce.Length != NonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be {NonceSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        ulong k0 = BinaryPrimitives.ReadUInt32BigEndian(key[..4]);
        ulong k1 = BinaryPrimitives.ReadUInt64BigEndian(key[4..12]);
        ulong k2 = BinaryPrimitives.ReadUInt64BigEndian(key[12..20]);
        ulong k3 = BinaryPrimitives.ReadUInt64BigEndian(key[20..]);
        ulong n0 = BinaryPrimitives.ReadUInt64BigEndian(nonce[..4]);
        ulong n1 = BinaryPrimitives.ReadUInt64BigEndian(nonce[4..]);

        x0 = 0xc0400c0600000000 | k0;
        x1 = k1;
        x2 = k2;
        x3 = k3 << 32 | n0;
        x4 = n1;
        Permutation(rounds: 12);
        x2 ^= k0 << 32 | k1 >> 32;
        x3 ^= k1 << 32 | k2 >> 32;
        x4 ^= k2 << 32 | k3 << 32;

        int i = 0;
        Span<byte> padding = stackalloc byte[Rate];
        if (associatedData.Length != 0) {
            while (i + Rate <= associatedData.Length) {
                x0 ^= BinaryPrimitives.ReadUInt64BigEndian(associatedData.Slice(i, Rate));
                Permutation(rounds: 6);
                i += Rate;
            }
            padding.Clear();
            if (associatedData.Length % Rate != 0) {
                associatedData[i..].CopyTo(padding);
            }
            padding[associatedData.Length % Rate] = 0x80;
            x0 ^= BinaryPrimitives.ReadUInt64BigEndian(padding);
            Permutation(rounds: 6);
        }
        x4 ^= 1;

        i = 0;
        while (i + Rate <= plaintext.Length) {
            ulong c = BinaryPrimitives.ReadUInt64BigEndian(ciphertext.Slice(i, Rate));
            BinaryPrimitives.WriteUInt64BigEndian(plaintext.Slice(i, Rate), x0 ^ c);
            x0 = c;
            Permutation(rounds: 6);
            i += Rate;
        }
        padding.Clear();
        if (plaintext.Length % Rate != 0) {
            ciphertext[i..^TagSize].CopyTo(padding);
            BinaryPrimitives.WriteUInt64BigEndian(padding, x0 ^ BinaryPrimitives.ReadUInt64BigEndian(padding));
            padding[..(plaintext.Length % Rate)].CopyTo(plaintext[i..]);
            padding[(plaintext.Length % Rate)..].Clear();
        }
        padding[plaintext.Length % Rate] = 0x80;
        x0 ^= BinaryPrimitives.ReadUInt64BigEndian(padding);

        x1 ^= k0 << 32 | k1 >> 32;
        x2 ^= k1 << 32 | k2 >> 32;
        x3 ^= k2 << 32 | k3 << 32;
        Permutation(rounds: 12);
        x2 ^= k0 << 32 | k1 >> 32;
        x3 ^= k1 << 32 | k2 >> 32;
        x4 ^= k2 << 32 | k3 << 32;
        Span<byte> tag = stackalloc byte[TagSize];
        BinaryPrimitives.WriteUInt64BigEndian(tag[..8], x2);
        BinaryPrimitives.WriteUInt64BigEndian(tag[8..16], x3);
        BinaryPrimitives.WriteUInt64BigEndian(tag[16..], x4);

        bool valid = CryptographicOperations.FixedTimeEquals(tag, ciphertext[^TagSize..]);
        ZeroState();
        CryptographicOperations.ZeroMemory(tag);
        CryptographicOperations.ZeroMemory(padding);

        if (!valid) {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException();
        }
    }

    private static void Permutation(int rounds)
    {
        ulong t0, t1, t2, t3, t4;
        for (ulong i = (ulong)(12 - rounds); i < 12; i++) {
            x2 ^= ((0xf - i) << 4) | i;

            x0 ^= x4; x4 ^= x3; x2 ^= x1;
            t0 = x0; t1 = x1; t2 = x2; t3 = x3; t4 = x4;
            t0 =~ t0; t1 =~ t1; t2 =~ t2; t3 =~ t3; t4 =~ t4;
            t0 &= x1; t1 &= x2; t2 &= x3; t3 &= x4; t4 &= x0;
            x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
            x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 =~ x2;

            x0 ^= ulong.RotateRight(x0, 19) ^ ulong.RotateRight(x0, 28);
            x1 ^= ulong.RotateRight(x1, 61) ^ ulong.RotateRight(x1, 39);
            x2 ^= ulong.RotateRight(x2, 1) ^ ulong.RotateRight(x2, 6);
            x3 ^= ulong.RotateRight(x3, 10) ^ ulong.RotateRight(x3, 17);
            x4 ^= ulong.RotateRight(x4, 7) ^ ulong.RotateRight(x4, 41);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static void ZeroState()
    {
        x0 = 0; x1 = 0; x2 = 0; x3 = 0; x4 = 0;
    }
}
