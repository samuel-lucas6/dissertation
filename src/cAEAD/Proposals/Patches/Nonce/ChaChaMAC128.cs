using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;

namespace cAEAD;

public static class ChaChaMAC128
{
    public const int KeySize = 32;
    public const int TagSize = 32;
    private const int Rate = 16;
    private static uint x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;

    public static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> message, ReadOnlySpan<byte> key)
    {
        if (tag.Length != TagSize) { throw new ArgumentOutOfRangeException(nameof(tag), tag.Length, $"{nameof(tag)} must be {TagSize} bytes long."); }
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        // NORX 32 constants u0-u7
        x0 = 0x0454EDAB;
        x1 = 0xAC6851CC;
        x2 = 0xB707322F;
        x3 = 0xA0C7C90D;
        x4 = BinaryPrimitives.ReadUInt32LittleEndian(key[..4]);
        x5 = BinaryPrimitives.ReadUInt32LittleEndian(key[4..8]);
        x6 = BinaryPrimitives.ReadUInt32LittleEndian(key[8..12]);
        x7 = BinaryPrimitives.ReadUInt32LittleEndian(key[12..16]);
        x8 = BinaryPrimitives.ReadUInt32LittleEndian(key[16..20]);
        x9 = BinaryPrimitives.ReadUInt32LittleEndian(key[20..24]);
        x10 = BinaryPrimitives.ReadUInt32LittleEndian(key[24..28]);
        x11 = BinaryPrimitives.ReadUInt32LittleEndian(key[28..]);
        x12 = 0x99AB09AC;
        x13 = 0xA643466D;
        x14 = 0x21C22362;
        x15 = 0x1230C950;
        Permute();

        int i = 0;
        Span<byte> padding = stackalloc byte[Rate];
        while (i + Rate <= message.Length) {
            x0 ^= BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(i, 4));
            x1 ^= BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(i + 4, 4));
            x2 ^= BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(i + 8, 4));
            x3 ^= BinaryPrimitives.ReadUInt32LittleEndian(message.Slice(i + 12, 4));
            x15 ^= 1;
            Permute();
            i += Rate;
        }
        padding.Clear();
        message[i..].CopyTo(padding);
        padding[message.Length % Rate] = 0x80;
        x0 ^= BinaryPrimitives.ReadUInt32LittleEndian(padding[..4]);
        x1 ^= BinaryPrimitives.ReadUInt32LittleEndian(padding[4..8]);
        x2 ^= BinaryPrimitives.ReadUInt32LittleEndian(padding[8..12]);
        x3 ^= BinaryPrimitives.ReadUInt32LittleEndian(padding[12..]);

        x15 ^= 2;
        Permute();
        BinaryPrimitives.WriteUInt32LittleEndian(tag[..4], x0);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[4..8], x1);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[8..12], x2);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[12..16], x3);
        x15 ^= 2;
        Permute();
        BinaryPrimitives.WriteUInt32LittleEndian(tag[16..20], x0);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[20..24], x1);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[24..28], x2);
        BinaryPrimitives.WriteUInt32LittleEndian(tag[28..], x3);

        ZeroState();
        CryptographicOperations.ZeroMemory(padding);
    }

    private static void Permute()
    {
        for (int i = 0; i < 10; i++) {
            (x0, x4, x8, x12) = QuarterRound(x0, x4, x8, x12);
            (x1, x5, x9, x13) = QuarterRound(x1, x5, x9, x13);
            (x2, x6, x10, x14) = QuarterRound(x2, x6, x10, x14);
            (x3, x7, x11, x15) = QuarterRound(x3, x7, x11, x15);
            (x0, x5, x10, x15) = QuarterRound(x0, x5, x10, x15);
            (x1, x6, x11, x12) = QuarterRound(x1, x6, x11, x12);
            (x2, x7, x8, x13) = QuarterRound(x2, x7, x8, x13);
            (x3, x4, x9, x14) = QuarterRound(x3, x4, x9, x14);
        }
    }

    private static (uint a, uint b, uint c, uint d) QuarterRound(uint a, uint b, uint c, uint d)
    {
        a += b;
        d ^= a;
        d = uint.RotateLeft(d, 16);
        c += d;
        b ^= c;
        b = uint.RotateLeft(b, 12);
        a += b;
        d ^= a;
        d = uint.RotateLeft(d, 8);
        c += d;
        b ^= c;
        b = uint.RotateLeft(b, 7);
        return (a, b, c, d);
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    private static void ZeroState()
    {
        x0 = 0;
        x1 = 0;
        x2 = 0;
        x3 = 0;
        x4 = 0;
        x5 = 0;
        x6 = 0;
        x7 = 0;
        x8 = 0;
        x9 = 0;
        x10 = 0;
        x11 = 0;
        x12 = 0;
        x13 = 0;
        x14 = 0;
        x15 = 0;
    }
}
