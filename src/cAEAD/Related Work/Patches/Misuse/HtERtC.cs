using System.Security.Cryptography;
using Geralt;

namespace cAEAD;

// https://eprint.iacr.org/2022/268
public static class HtERtC
{
    public const int KeySize = RtC.KeySize;
    // 96-bit nonce to match AES-GCM-SIV
    public const int NonceSize = RtC.NonceSize;
    public const int TagSize = RtC.TagSize;
    public const int CommitmentSize = RtC.CommitmentSize;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Validation.NotLessThanMin(nameof(associatedData), associatedData.Length, NonceSize);

        Span<byte> subkey = stackalloc byte[KeySize];
        ReadOnlySpan<byte> nonce = associatedData[..NonceSize];
        DeriveKey(subkey, key, nonce, associatedData[NonceSize..]);

        RtC.Encrypt(ciphertext, plaintext, subkey, associatedData: nonce);
        CryptographicOperations.ZeroMemory(subkey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Validation.NotLessThanMin(nameof(associatedData), associatedData.Length, NonceSize);

        Span<byte> subkey = stackalloc byte[KeySize];
        ReadOnlySpan<byte> nonce = associatedData[..NonceSize];
        DeriveKey(subkey, key, nonce, associatedData[NonceSize..]);

        RtC.Decrypt(plaintext, ciphertext, subkey, associatedData: nonce);
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
