using System.Security.Cryptography;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace cAEAD;

// https://eprint.iacr.org/2020/1456
public static class PaddingFix
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

        Span<byte> paddedPlaintext = new byte[plaintext.Length + CommitmentSize];
        plaintext.CopyTo(paddedPlaintext[CommitmentSize..]);
        ChaCha20Poly1305.Encrypt(ciphertext, paddedPlaintext, nonce, key, associatedData);
        CryptographicOperations.ZeroMemory(paddedPlaintext);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> paddedPlaintext = new byte[plaintext.Length + CommitmentSize];
        ChaCha20Poly1305.Decrypt(paddedPlaintext, ciphertext, nonce, key, associatedData);

        if (!ConstantTime.IsAllZeros(paddedPlaintext[..CommitmentSize])) {
            CryptographicOperations.ZeroMemory(paddedPlaintext);
            throw new CryptographicException();
        }

        paddedPlaintext[CommitmentSize..].CopyTo(plaintext);
        CryptographicOperations.ZeroMemory(paddedPlaintext);
    }
}
