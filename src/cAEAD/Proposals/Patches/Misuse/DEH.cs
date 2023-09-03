using System.Security.Cryptography;
using Geralt;

namespace cAEAD;

public static class DEH
{
    public const int KeySize = 32;
    public const int NonceSize = ChaCha20.NonceSize;
    public const int TagSize = Daence.TagSize;
    public const int CommitmentSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Validation.NotLessThanMin(nameof(associatedData), associatedData.Length, NonceSize);

        // Daence requires a 512-bit key, so encKey || comKey is used since BLAKE2b is not an XOF
        Span<byte> subkeys = stackalloc byte[BLAKE2b.MaxHashSize], encKey = subkeys[..ChaCha20.KeySize], comKey = subkeys[ChaCha20.KeySize..];
        // Daence doesn't support a nonce, only associated data
        ReadOnlySpan<byte> nonce = associatedData[..NonceSize];
        DeriveKeys(subkeys, key, nonce, associatedData[NonceSize..]);

        Daence.Encrypt(ciphertext[CommitmentSize..], plaintext, subkeys, associatedData: nonce);
        ComputeCommitment(ciphertext[..CommitmentSize], comKey, ciphertext[^TagSize..]);
        CryptographicOperations.ZeroMemory(subkeys);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Validation.NotLessThanMin(nameof(associatedData), associatedData.Length, NonceSize);

        Span<byte> subkeys = stackalloc byte[BLAKE2b.MaxHashSize], encKey = subkeys[..ChaCha20.KeySize], comKey = subkeys[ChaCha20.KeySize..];
        ReadOnlySpan<byte> nonce = associatedData[..NonceSize];
        DeriveKeys(subkeys, key, nonce, associatedData[NonceSize..]);

        Span<byte> commitment = stackalloc byte[CommitmentSize];
        ComputeCommitment(commitment, comKey, ciphertext[^TagSize..]);

        if (!ConstantTime.Equals(ciphertext[..CommitmentSize], commitment)) {
            CryptographicOperations.ZeroMemory(subkeys);
            CryptographicOperations.ZeroMemory(commitment);
            throw new CryptographicException();
        }

        Daence.Decrypt(plaintext, ciphertext[CommitmentSize..], subkeys, associatedData: nonce);
        CryptographicOperations.ZeroMemory(subkeys);
        CryptographicOperations.ZeroMemory(commitment);
    }

    private static void DeriveKeys(Span<byte> subkeys, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData)
    {
        using var blake2b = new IncrementalBLAKE2b(subkeys.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Finalize(subkeys);
    }

    private static void ComputeCommitment(Span<byte> commitment, ReadOnlySpan<byte> comKey, ReadOnlySpan<byte> tag)
    {
        using var blake2b = new IncrementalBLAKE2b(commitment.Length, comKey);
        blake2b.Update(tag);
        blake2b.Finalize(commitment);
    }
}
