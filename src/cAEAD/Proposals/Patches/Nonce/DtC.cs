using System.Security.Cryptography;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace cAEAD;

public static class DtC
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

        Span<byte> subkeys = stackalloc byte[ChaCha20.BlockSize], encKey = subkeys[..ChaCha20.KeySize], comKey = subkeys[ChaCha20.KeySize..];
        ChaCha20.Fill(subkeys, nonce, key);

        comKey.CopyTo(ciphertext[..CommitmentSize]);
        ChaCha20Poly1305.Encrypt(ciphertext[CommitmentSize..], plaintext, nonce, encKey, associatedData);
        CryptographicOperations.ZeroMemory(subkeys);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkeys = stackalloc byte[ChaCha20.BlockSize], encKey = subkeys[..ChaCha20.KeySize], comKey = subkeys[ChaCha20.KeySize..];
        ChaCha20.Fill(subkeys, nonce, key);

        if (!ConstantTime.Equals(ciphertext[..CommitmentSize], comKey)) {
            CryptographicOperations.ZeroMemory(subkeys);
            throw new CryptographicException();
        }

        ChaCha20Poly1305.Decrypt(plaintext, ciphertext[CommitmentSize..], nonce, encKey, associatedData);
        CryptographicOperations.ZeroMemory(subkeys);
    }
}
