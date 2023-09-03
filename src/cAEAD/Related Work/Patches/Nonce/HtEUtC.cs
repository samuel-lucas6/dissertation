using System.Security.Cryptography;
using Geralt;

namespace cAEAD;

// https://eprint.iacr.org/2022/268
public static class HtEUtC
{
    public const int KeySize = UtC.KeySize;
    public const int NonceSize = UtC.NonceSize;
    public const int TagSize = UtC.TagSize;
    public const int CommitmentSize = UtC.CommitmentSize;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkey = stackalloc byte[KeySize];
        DeriveKey(subkey, key, nonce, associatedData);

        UtC.Encrypt(ciphertext, plaintext, nonce, subkey, associatedData: ReadOnlySpan<byte>.Empty);
        CryptographicOperations.ZeroMemory(subkey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkey = stackalloc byte[KeySize];
        DeriveKey(subkey, key, nonce, associatedData);

        UtC.Decrypt(plaintext, ciphertext, nonce, subkey, associatedData: ReadOnlySpan<byte>.Empty);
        CryptographicOperations.ZeroMemory(subkey);
    }

    private static void DeriveKey(Span<byte> subkey, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData)
    {
        using var blake2b = new IncrementalBLAKE2b(subkey.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Finalize(subkey);
    }
}
