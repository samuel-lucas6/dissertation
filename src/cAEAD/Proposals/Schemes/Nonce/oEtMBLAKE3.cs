using System.Security.Cryptography;
using System.Buffers.Binary;
using Blake3;
using Geralt;

namespace cAEAD;

public static class oEtMBLAKE3
{
    public const int KeySize = ChaCha20.KeySize;
    public const int NonceSize = ChaCha20.NonceSize;
    public const int TagSize = Blake3.Hash.Size;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> ciphertextCore = ciphertext[..^TagSize];
        ChaCha20.Encrypt(ciphertextCore, plaintext, nonce, key);

        ComputeTag(ciphertext[^TagSize..], associatedData, nonce, ciphertextCore, key);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> computedTag = stackalloc byte[TagSize];
        ReadOnlySpan<byte> ciphertextCore = ciphertext[..^TagSize];
        ComputeTag(computedTag, associatedData, nonce, ciphertextCore, key);

        bool valid = ConstantTime.Equals(ciphertext[^TagSize..], computedTag);
        CryptographicOperations.ZeroMemory(computedTag);

        if (!valid) {
            throw new CryptographicException();
        }

        ChaCha20.Decrypt(plaintext, ciphertextCore, nonce, key);
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertextCore, ReadOnlySpan<byte> key)
    {
        using var blake3 = Hasher.NewKeyed(key);
        blake3.Update(associatedData);
        blake3.Update(nonce);
        blake3.UpdateWithJoin(ciphertextCore);

        Span<byte> lengths = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[..8], (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(lengths[8..], (ulong)ciphertextCore.Length);
        blake3.Update(lengths);
        blake3.Finalize(tag);
    }
}
