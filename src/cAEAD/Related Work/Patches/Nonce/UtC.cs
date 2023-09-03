using System.Security.Cryptography;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace cAEAD;

// https://eprint.iacr.org/2022/268
public static class UtC
{
    public const int KeySize = ChaCha20Poly1305.KeySize;
    public const int NonceSize = ChaCha20Poly1305.NonceSize;
    public const int TagSize = ChaCha20Poly1305.TagSize;
    public const int CommitmentSize = CX.BlockSize;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkey = stackalloc byte[KeySize];
        CX.Derive(ciphertext[..CommitmentSize], subkey, nonce, key);

        ChaCha20Poly1305.Encrypt(ciphertext[CommitmentSize..], plaintext, nonce, subkey, associatedData);
        CryptographicOperations.ZeroMemory(subkey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> commitment = stackalloc byte[CommitmentSize], subkey = stackalloc byte[KeySize];
        CX.Derive(commitment, subkey, nonce, key);

        bool valid = ConstantTime.Equals(ciphertext[..CommitmentSize], commitment);
        CryptographicOperations.ZeroMemory(commitment);

        if (!valid) {
            CryptographicOperations.ZeroMemory(subkey);
            throw new CryptographicException();
        }

        ChaCha20Poly1305.Decrypt(plaintext, ciphertext[CommitmentSize..], nonce, subkey, associatedData);
        CryptographicOperations.ZeroMemory(subkey);
    }
}
