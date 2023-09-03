using System.Security.Cryptography;
using Geralt;

namespace cAEAD;

public static class AEGIS256DFV4
{
    public const int KeySize = AEGIS256.KeySize;
    public const int NonceSize = AEGIS256.NonceSize;
    public const int TagSize = AEGIS256.MaxTagSize + NonceSize;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkey = stackalloc byte[KeySize];
        DeriveKey(subkey, key, nonce, associatedData);

        Span<byte> iv = ciphertext[..NonceSize];
        DeriveIV(iv, key, subkey, plaintext);

        AEGIS256.Encrypt(ciphertext[NonceSize..], plaintext, iv, subkey, associatedData: ReadOnlySpan<byte>.Empty, AEGIS256.MaxTagSize);
        CryptographicOperations.ZeroMemory(subkey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> subkey = stackalloc byte[KeySize];
        DeriveKey(subkey, key, nonce, associatedData);

        AEGIS256.Decrypt(plaintext, ciphertext[NonceSize..], ciphertext[..NonceSize], subkey, associatedData: ReadOnlySpan<byte>.Empty, AEGIS256.MaxTagSize);
        CryptographicOperations.ZeroMemory(subkey);
    }

    private static void DeriveKey(Span<byte> subkey, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> associatedData)
    {
        using var aegis = new AEGIS256Mac(key);
        aegis.Update("dfv4-kdf"u8);
        aegis.Update(nonce);
        aegis.Update(associatedData);
        aegis.Finalize(subkey);
    }

    private static void DeriveIV(Span<byte> iv, ReadOnlySpan<byte> key, ReadOnlySpan<byte> subkey, ReadOnlySpan<byte> plaintext)
    {
        using var aegis = new AEGIS256Mac(key);
        aegis.Update("dfv4-siv"u8);
        aegis.Update(subkey);
        aegis.Update(plaintext);
        aegis.Finalize(iv);
    }
}
