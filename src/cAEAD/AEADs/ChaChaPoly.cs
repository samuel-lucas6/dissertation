﻿using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace cAEAD;

// https://www.rfc-editor.org/rfc/rfc8439
public static class ChaChaPoly
{
    public const int KeySize = ChaCha20Poly1305.KeySize;
    public const int NonceSize = ChaCha20Poly1305.NonceSize;
    public const int TagSize = ChaCha20Poly1305.TagSize;
    private const uint Counter = 1;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize];
        ChaCha20.Fill(block0, nonce, key);
        Span<byte> macKey = block0[..Poly1305.KeySize];

        Span<byte> ciphertextCore = ciphertext[..^TagSize];
        ChaCha20.Encrypt(ciphertextCore, plaintext, nonce, key, Counter);

        ComputeTag(ciphertext[^TagSize..], associatedData, ciphertextCore, macKey);
        CryptographicOperations.ZeroMemory(block0);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize];
        ChaCha20.Fill(block0, nonce, key);
        Span<byte> macKey = block0[..Poly1305.KeySize];

        ReadOnlySpan<byte> ciphertextCore = ciphertext[..^TagSize];
        Span<byte> tag = stackalloc byte[TagSize];
        ComputeTag(tag, associatedData, ciphertextCore, macKey);

        bool valid = ConstantTime.Equals(ciphertext[^TagSize..], tag);
        CryptographicOperations.ZeroMemory(block0);
        CryptographicOperations.ZeroMemory(tag);

        if (!valid) {
            throw new CryptographicException();
        }

        ChaCha20.Decrypt(plaintext, ciphertextCore, nonce, key, Counter);
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertextCore, ReadOnlySpan<byte> macKey)
    {
        Span<byte> padding = stackalloc byte[16];
        padding.Clear();

        using var poly1305 = new IncrementalPoly1305(macKey);
        poly1305.Update(associatedData);
        if (associatedData.Length % 16 != 0) {
            poly1305.Update(padding[(associatedData.Length % 16)..]);
        }

        poly1305.Update(ciphertextCore);
        if (ciphertextCore.Length % 16 != 0) {
            poly1305.Update(padding[(ciphertextCore.Length % 16)..]);
        }

        BinaryPrimitives.WriteUInt64LittleEndian(padding[..8], (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(padding[8..], (ulong)ciphertextCore.Length);
        poly1305.Update(padding);
        poly1305.Finalize(tag);
    }
}
