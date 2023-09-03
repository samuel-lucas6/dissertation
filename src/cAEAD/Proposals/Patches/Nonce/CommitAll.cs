using System.Security.Cryptography;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace cAEAD;

public static class CommitAll
{
    public const int KeySize = ChaCha20Poly1305.KeySize;
    public const int NonceSize = ChaCha20Poly1305.NonceSize;
    public const int TagSize = ChaCha20Poly1305.TagSize;
    public const int CommitmentSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkeys = stackalloc byte[BLAKE2b.MaxHashSize], encKey = subkeys[..KeySize], comKey = subkeys[KeySize..];
        DeriveKeys(subkeys, key, nonce, associatedData);

        comKey.CopyTo(ciphertext[..CommitmentSize]);
        ChaCha20Poly1305.Encrypt(ciphertext[CommitmentSize..], plaintext, nonce, encKey, associatedData: ReadOnlySpan<byte>.Empty);
        CryptographicOperations.ZeroMemory(subkeys);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkeys = stackalloc byte[BLAKE2b.MaxHashSize], encKey = subkeys[..KeySize], comKey = subkeys[KeySize..];
        DeriveKeys(subkeys, key, nonce, associatedData);

        if (!ConstantTime.Equals(ciphertext[..CommitmentSize], comKey)) {
            CryptographicOperations.ZeroMemory(subkeys);
            throw new CryptographicException();
        }

        ChaCha20Poly1305.Decrypt(plaintext, ciphertext[CommitmentSize..], nonce, encKey, associatedData: ReadOnlySpan<byte>.Empty);
        CryptographicOperations.ZeroMemory(subkeys);
    }

    private static void DeriveKeys(Span<byte> subkeys, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData)
    {
        using var blake2b = new IncrementalBLAKE2b(subkeys.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Finalize(subkeys);
    }
}
