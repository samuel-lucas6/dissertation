using System.Security.Cryptography;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace cAEAD;

// https://iacr.org/submit/files/slides/2023/rwc/rwc2023/112/slides.pptx
public static class ContextHashing
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

        ComputeTag(ciphertext[..CommitmentSize], key, nonce, associatedData);
        ChaCha20Poly1305.Encrypt(ciphertext[CommitmentSize..], plaintext, nonce, key, associatedData);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> commitment = stackalloc byte[CommitmentSize];
        ComputeTag(commitment, key, nonce, associatedData);

        bool valid = ConstantTime.Equals(ciphertext[..CommitmentSize], commitment);
        CryptographicOperations.ZeroMemory(commitment);

        if (!valid) {
            throw new CryptographicException();
        }

        ChaCha20Poly1305.Decrypt(plaintext, ciphertext[CommitmentSize..], nonce, key, associatedData);
    }

    private static void ComputeTag(Span<byte> commitment, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData)
    {
        using var blake2b = new IncrementalBLAKE2b(commitment.Length, key);
        blake2b.Update(nonce);
        blake2b.Update(associatedData);
        blake2b.Finalize(commitment);
    }
}
