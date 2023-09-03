using System.Security.Cryptography;
using Geralt;

namespace cAEAD;

// https://doc.libsodium.org/secret-key_cryptography/aead#robustness
public static class LibsodiumTransformMisuse
{
    public const int KeySize = Daence.KeySize;
    // 96-bit nonce to match AES-GCM-SIV
    public const int NonceSize = ChaCha20.NonceSize;
    public const int TagSize = Daence.TagSize;
    public const int CommitmentSize = 32;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Validation.NotLessThanMin(nameof(associatedData), associatedData.Length, NonceSize);

        // Daence doesn't support a nonce, only associated data
        ReadOnlySpan<byte> nonce = associatedData[..NonceSize];
        Daence.Encrypt(ciphertext[CommitmentSize..], plaintext, key, associatedData);
        ComputeCommitment(ciphertext[..CommitmentSize], key, nonce, ciphertext[^TagSize..], associatedData[NonceSize..]);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Validation.NotLessThanMin(nameof(associatedData), associatedData.Length, NonceSize);

        Span<byte> commitment = stackalloc byte[CommitmentSize];
        ReadOnlySpan<byte> nonce = associatedData[..NonceSize];
        ComputeCommitment(commitment, key, nonce, ciphertext[^TagSize..], associatedData[NonceSize..]);

        bool valid = ConstantTime.Equals(ciphertext[..CommitmentSize], commitment);
        CryptographicOperations.ZeroMemory(commitment);

        if (!valid) {
            throw new CryptographicException();
        }

        Daence.Decrypt(plaintext, ciphertext[CommitmentSize..], key, associatedData);
    }

    private static void ComputeCommitment(Span<byte> commitment, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> associatedData)
    {
        using var blake2b = new IncrementalBLAKE2b(commitment.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(tag);
        blake2b.Update(associatedData);
        blake2b.Finalize(commitment);
    }
}
