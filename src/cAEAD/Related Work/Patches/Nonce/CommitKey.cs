using System.Security.Cryptography;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace cAEAD;

// https://eprint.iacr.org/2020/1456
public static class CommitKey
{
    public const int KeySize = ChaCha20Poly1305.KeySize;
    public const int NonceSize = ChaCha20Poly1305.NonceSize;
    public const int TagSize = ChaCha20Poly1305.TagSize;
    public const int CommitmentSize = 32;

    public enum Type
    {
        I = 1,
        II = 2,
        III = 3,
        IV = 4
    }

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, Type type = Type.IV)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> encKey = stackalloc byte[KeySize], comKey = ciphertext[^CommitmentSize..];
        DeriveKeys(encKey, comKey, key, nonce, (byte)type);

        ChaCha20Poly1305.Encrypt(ciphertext[..^CommitmentSize], plaintext, nonce, encKey, associatedData);
        CryptographicOperations.ZeroMemory(encKey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default, Type type = Type.IV)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> encKey = stackalloc byte[KeySize], comKey = stackalloc byte[KeySize];
        DeriveKeys(encKey, comKey, key, nonce, (byte)type);

        ChaCha20Poly1305.Decrypt(plaintext, ciphertext[..^CommitmentSize], nonce, encKey, associatedData);
        CryptographicOperations.ZeroMemory(encKey);

        bool valid = ConstantTime.Equals(ciphertext[^CommitmentSize..], comKey);
        CryptographicOperations.ZeroMemory(comKey);

        if (!valid) {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException();
        }
    }

    private static void DeriveKeys(Span<byte> encKey, Span<byte> comKey, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, byte type)
    {
        Span<byte> encLabel = stackalloc byte[] { 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, type, 0x01 };
        Span<byte> comLabel = stackalloc byte[] { 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, type, 0x02 };

        using var encPrf = new IncrementalBLAKE2b(encKey.Length, key);
        encPrf.Update(encLabel);
        if (type is 2 or 4) {
            encPrf.Update(nonce);
        }
        encPrf.Finalize(encKey);

        using var comPrf = new IncrementalBLAKE2b(comKey.Length, key);
        comPrf.Update(comLabel);
        if (type is 3 or 4) {
            comPrf.Update(nonce);
        }
        comPrf.Finalize(comKey);
    }
}
