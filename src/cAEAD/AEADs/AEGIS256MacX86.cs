using Aes = System.Runtime.Intrinsics.X86.Aes;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Runtime.Intrinsics;
using System.Buffers.Binary;

namespace cAEAD;

internal static class AEGIS256MacX86
{
    private const int BlockSize = 16;
    private static Vector128<byte> S0, S1, S2, S3, S4, S5;
    private static byte[] _buffer = new byte[BlockSize];
    private static int _bytesBuffered;
    private static ulong _messageLength;

    internal static bool IsSupported() => Aes.IsSupported;

    internal static void Initialize(ReadOnlySpan<byte> key)
    {
        ReadOnlySpan<byte> c = stackalloc byte[]
        {
            0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
            0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
        };
        Vector128<byte> c0 = Vector128.Create(c[..BlockSize]);
        Vector128<byte> c1 = Vector128.Create(c[BlockSize..]);
        Vector128<byte> k0 = Vector128.Create(key[..BlockSize]);
        Vector128<byte> k1 = Vector128.Create(key[BlockSize..]);
        Vector128<byte> n0 = Vector128<byte>.Zero;
        Vector128<byte> n1 = Vector128<byte>.Zero;

        S0 = k0 ^ n0;
        S1 = k1 ^ n1;
        S2 = c1;
        S3 = c0;
        S4 = k0 ^ c0;
        S5 = k1 ^ c1;

        for (int i = 0; i < 4; i++) {
            UpdateState(k0);
            UpdateState(k1);
            UpdateState(k0 ^ n0);
            UpdateState(k1 ^ n1);
        }
    }

    private static void UpdateState(Vector128<byte> message)
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

    internal static void Update(ReadOnlySpan<byte> message)
    {
        int i = 0;
        _messageLength += (ulong)message.Length;
        if (_bytesBuffered != 0 && _bytesBuffered + message.Length >= BlockSize) {
            Span<byte> b = _buffer;
            message[..(b.Length - _bytesBuffered)].CopyTo(b[_bytesBuffered..]);
            Absorb(b);
            i += b.Length - _bytesBuffered;
            _bytesBuffered = 0;
            b.Clear();
        }

        while (i + BlockSize <= message.Length) {
            Absorb(message.Slice(i, BlockSize));
            i += BlockSize;
        }

        if (message.Length % BlockSize != 0) {
            message[i..].CopyTo(_buffer.AsSpan()[_bytesBuffered..]);
            _bytesBuffered += message.Length - i;
        }
    }

    private static void Absorb(ReadOnlySpan<byte> associatedData)
    {
        Vector128<byte> ad = Vector128.Create(associatedData);
        UpdateState(ad);
    }

    internal static void Finalize(Span<byte> tag)
    {
        if (_bytesBuffered != 0) {
            Span<byte> padding = stackalloc byte[BlockSize];
            padding.Clear();
            _buffer.CopyTo(padding);
            Absorb(padding);
            CryptographicOperations.ZeroMemory(padding);
        }

        var b = new byte[BlockSize]; Span<byte> bb = b;
        BinaryPrimitives.WriteUInt64LittleEndian(bb[..8], _messageLength * 8);
        BinaryPrimitives.WriteUInt64LittleEndian(bb[8..], 0);

        Vector128<byte> t = S3 ^ Vector128.Create(b);

        for (int i = 0; i < 7; i++) {
            UpdateState(t);
        }

        if (tag.Length == AEGIS256Mac.MinTagSize) {
            Vector128<byte> a = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5;
            a.CopyTo(tag);
        }
        else {
            Vector128<byte> a1 = S0 ^ S1 ^ S2;
            Vector128<byte> a2 = S3 ^ S4 ^ S5;
            a1.CopyTo(tag[..BlockSize]);
            a2.CopyTo(tag[BlockSize..]);
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    internal static void ZeroState()
    {
        S0 = Vector128<byte>.Zero;
        S1 = Vector128<byte>.Zero;
        S2 = Vector128<byte>.Zero;
        S3 = Vector128<byte>.Zero;
        S4 = Vector128<byte>.Zero;
        CryptographicOperations.ZeroMemory(_buffer);
        _bytesBuffered = 0;
        _messageLength = 0;
    }
}
