using System.Security.Cryptography;
using System.Buffers.Binary;
using Geralt;

namespace cAEAD;

// https://old.reddit.com/r/crypto/comments/opm10n/do_i_need_a_key_committing_aead_to_be_random_key/
public static class VaillantTransform
{
    public const int KeySize = ChaCha20.KeySize;
    public const int NonceSize = ChaCha20.NonceSize;
    public const int TagSize = Poly1305.TagSize;
    public const int CommitmentSize = 32;
    private const uint Counter = 1;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize];
        ChaCha20.Fill(block0, nonce, key);
        Span<byte> macKey = block0[..Poly1305.KeySize], commitment = block0[Poly1305.KeySize..];
        commitment.CopyTo(ciphertext[..CommitmentSize]);

        Span<byte> ciphertextCore = ciphertext[CommitmentSize..^Poly1305.TagSize];
        ChaCha20.Encrypt(ciphertextCore, plaintext, nonce, key, Counter);

        ComputeTag(ciphertext[^Poly1305.TagSize..], associatedData, ciphertextCore, macKey);
        CryptographicOperations.ZeroMemory(macKey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData = default)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(nonce), nonce.Length, NonceSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);

        Span<byte> block0 = stackalloc byte[ChaCha20.BlockSize];
        ChaCha20.Fill(block0, nonce, key);
        Span<byte> macKey = block0[..Poly1305.KeySize], commitment = block0[Poly1305.KeySize..];

        ReadOnlySpan<byte> ciphertextCore = ciphertext[CommitmentSize..^Poly1305.TagSize];
        Span<byte> tag = stackalloc byte[Poly1305.TagSize];
        ComputeTag(tag, associatedData, ciphertextCore, macKey);
        CryptographicOperations.ZeroMemory(macKey);

        bool valid = ConstantTime.Equals(ciphertext[^Poly1305.TagSize..], tag);
        valid &= ConstantTime.Equals(ciphertext[..CommitmentSize], commitment);
        CryptographicOperations.ZeroMemory(tag);
        CryptographicOperations.ZeroMemory(commitment);

        if (!valid) {
            throw new CryptographicException();
        }

        ChaCha20.Decrypt(plaintext, ciphertextCore, nonce, key, Counter);
    }

    private static void ComputeTag(Span<byte> tag, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertextCore, ReadOnlySpan<byte> macKey)
    {
        Span<byte> padding = stackalloc byte[16];
        padding.Clear();

        using var poly1305 = new IncrementalPoly1305(macKey);
        poly1305.Update(associatedData);
        if (associatedData.Length % 16 != 0) {
            poly1305.Update(padding[(associatedData.Length % 16)..]);
        }

        poly1305.Update(ciphertextCore);
        if (ciphertextCore.Length % 16 != 0) {
            poly1305.Update(padding[(ciphertextCore.Length % 16)..]);
        }

        BinaryPrimitives.WriteUInt64LittleEndian(padding[..8], (ulong)associatedData.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(padding[8..], (ulong)ciphertextCore.Length);
        poly1305.Update(padding);
        poly1305.Finalize(tag);
    }
}
