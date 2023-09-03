using System.Security.Cryptography;
using Geralt;

namespace cAEAD;

public static class cSIVBLAKE2b
{
    public const int KeySize = XChaCha20.KeySize;
    public const int NonceSize = XChaCha20.NonceSize;
    public const int TagSize = BLAKE2b.TagSize;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkeys = stackalloc byte[KeySize * 2], macKey = subkeys[..KeySize], encKey = subkeys[KeySize..];
        DeriveKeys(subkeys, key, nonce, associatedData);

        Span<byte> tag = ciphertext[^TagSize..];
        ComputeTag(tag, plaintext, macKey);

        XChaCha20.Encrypt(ciphertext[..^TagSize], plaintext, tag[..NonceSize], encKey);
        CryptographicOperations.ZeroMemory(subkeys);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkeys = stackalloc byte[KeySize * 2], macKey = subkeys[..KeySize], encKey = subkeys[KeySize..];
        DeriveKeys(subkeys, key, nonce, associatedData);

        ReadOnlySpan<byte> tag = ciphertext[^TagSize..];
        XChaCha20.Decrypt(plaintext, ciphertext[..^TagSize], tag[..NonceSize], encKey);

        Span<byte> computedTag = stackalloc byte[TagSize];
        ComputeTag(computedTag, plaintext, macKey);

        bool valid = ConstantTime.Equals(tag, computedTag);
        CryptographicOperations.ZeroMemory(computedTag);
        CryptographicOperations.ZeroMemory(subkeys);

        if (!valid) {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException();
        }
    }

    private static void DeriveKeys(Span<byte> subkeys, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData)
    {
        using var blake2 = new IncrementalBLAKE2b(subkeys.Length, key);
        blake2.Update(nonce);
        blake2.Update(associatedData);
        blake2.Finalize(subkeys);
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> macKey)
    {
        using var blake2 = new IncrementalBLAKE2b(tag.Length, macKey);
        blake2.Update(plaintext);
        blake2.Finalize(tag);
    }
}
