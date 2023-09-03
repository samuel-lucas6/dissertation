using System.Security.Cryptography;
using Blake3;
using Geralt;

namespace cAEAD;

public static class cEtMBLAKE3
{
    public const int KeySize = ChaCha20.KeySize;
    public const int NonceSize = ChaCha20.NonceSize;
    public const int TagSize = Blake3.Hash.Size;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkeys = stackalloc byte[KeySize * 2], encKey = subkeys[..KeySize], macKey = subkeys[KeySize..];
        DeriveKeys(subkeys, key, nonce, associatedData);

        Span<byte> ciphertextCore = ciphertext[..^TagSize];
        ChaCha20.Encrypt(ciphertextCore, plaintext, nonce, encKey);

        ComputeTag(ciphertext[^TagSize..], ciphertextCore, macKey);
        CryptographicOperations.ZeroMemory(subkeys);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkeys = stackalloc byte[KeySize * 2], encKey = subkeys[..KeySize], macKey = subkeys[KeySize..];
        DeriveKeys(subkeys, key, nonce, associatedData);

        Span<byte> computedTag = stackalloc byte[TagSize];
        ReadOnlySpan<byte> ciphertextCore = ciphertext[..^TagSize];
        ComputeTag(computedTag, ciphertextCore, macKey);

        bool valid = ConstantTime.Equals(ciphertext[^TagSize..], computedTag);
        CryptographicOperations.ZeroMemory(computedTag);

        if (!valid) {
            CryptographicOperations.ZeroMemory(subkeys);
            throw new CryptographicException();
        }

        ChaCha20.Decrypt(plaintext, ciphertextCore, nonce, encKey);
        CryptographicOperations.ZeroMemory(subkeys);
    }

    private static void DeriveKeys(Span<byte> subkeys, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData)
    {
        using var blake3 = Hasher.NewKeyed(key);
        blake3.Update(nonce);
        blake3.Update(associatedData);
        blake3.Finalize(subkeys);
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> ciphertextCore, ReadOnlySpan<byte> macKey)
    {
        using var blake3 = Hasher.NewKeyed(macKey);
        blake3.UpdateWithJoin(ciphertextCore);
        blake3.Finalize(tag);
    }
}
