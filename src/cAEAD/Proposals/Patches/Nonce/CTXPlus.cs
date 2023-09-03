using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace cAEAD;

public static class CTXPlus
{
    public const int KeySize = ChaCha20Poly1305.KeySize;
    public const int NonceSize = ChaCha20Poly1305.NonceSize;
    public const int TagSize = 20;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> ciphertextCore = ciphertext[..^(TagSize - Poly1305.TagSize)];
        ChaCha20Poly1305.Encrypt(ciphertextCore, plaintext, nonce, key, associatedData: ReadOnlySpan<byte>.Empty);
        ComputeNewTag(ciphertext[^TagSize..], key, nonce, associatedData, ciphertextCore[^Poly1305.TagSize..]);
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

        Span<byte> tag = stackalloc byte[Poly1305.TagSize];
        ReadOnlySpan<byte> ciphertextCore = ciphertext[..^TagSize];
        ComputeTag(tag, associatedData: ReadOnlySpan<byte>.Empty, ciphertextCore, macKey);
        CryptographicOperations.ZeroMemory(block0);

        Span<byte> newTag = stackalloc byte[TagSize];
        ComputeNewTag(newTag, key, nonce, associatedData, tag);
        CryptographicOperations.ZeroMemory(tag);

        bool valid = ConstantTime.Equals(ciphertext[^TagSize..], newTag);
        CryptographicOperations.ZeroMemory(newTag);

        if (!valid) {
            throw new CryptographicException();
        }

        ChaCha20.Decrypt(plaintext, ciphertextCore, nonce, key, counter: 1);
    }

    private static void ComputeNewTag(Span<byte> newTag, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> tag)
    {
        using var blake2b = new IncrementalBLAKE2b(newTag.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Update(tag);
        blake2b.Finalize(newTag);
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> macKey)
    {
        Span<byte> padding = stackalloc byte[16];
        padding.Clear();

        using var poly1305 = new IncrementalPoly1305(macKey);
        poly1305.Update(associatedData);
        if (associatedData.Length % 16 != 0) {
            poly1305.Update(padding[(associatedData.Length % 16)..]);
        }

        poly1305.Update(ciphertext);
        if (ciphertext.Length % 16 != 0) {
            poly1305.Update(padding[(ciphertext.Length % 16)..]);
        }

        BinaryPrimitives.WriteUInt64LittleEndian(padding[..8], (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(padding[8..], (ulong)ciphertext.Length);
        poly1305.Update(padding);
        poly1305.Finalize(tag);
    }
}
