using System.Security.Cryptography;
using Geralt;

namespace cAEAD;

// https://eprint.iacr.org/2022/268
public static class RtC
{
    public const int KeySize = 32;
    // 96-bit nonce to match AES-GCM-SIV
    public const int NonceSize = ChaCha20.NonceSize;
    public const int TagSize = Daence.TagSize;
    public const int CommitmentSize = CX.BlockSize;
    private const int BlockSize = 16;

    public static void Encrypt(Span<byte> ciphertext, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData)
    {
        Validation.EqualToSize(nameof(ciphertext), ciphertext.Length, plaintext.Length + CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Validation.NotLessThanMin(nameof(associatedData), associatedData.Length, NonceSize);

        Span<byte> subkeys = stackalloc byte[KeySize * 2], comKey = subkeys[..KeySize], encKey = subkeys[KeySize..];
        // Daence doesn't support a nonce, so nonce = associatedData[..NonceSize]
        ReadOnlySpan<byte> nonce = associatedData[..NonceSize];
        CX.Derive(comKey, encKey, nonce, key);

        // Daence also requires a 512-bit key, so comKey || encKey is used to avoid slowing CX down compared to RtC with AES-GCM-SIV
        Daence.Encrypt(ciphertext[CommitmentSize..], plaintext, subkeys, associatedData);

        DaviesMeyer(ciphertext[..CommitmentSize], ciphertext.Slice(CommitmentSize, BlockSize), comKey);
        CryptographicOperations.ZeroMemory(comKey);
        CryptographicOperations.ZeroMemory(encKey);
    }

    public static void Decrypt(Span<byte> plaintext, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> key, ReadOnlySpan<byte> associatedData)
    {
        Validation.NotLessThanMin(nameof(ciphertext), ciphertext.Length, CommitmentSize + TagSize);
        Validation.EqualToSize(nameof(plaintext), plaintext.Length, ciphertext.Length - CommitmentSize - TagSize);
        Validation.EqualToSize(nameof(key), key.Length, KeySize);
        Validation.NotLessThanMin(nameof(associatedData), associatedData.Length, NonceSize);

        Span<byte> subkeys = stackalloc byte[KeySize * 2], comKey = subkeys[..KeySize], encKey = subkeys[KeySize..];
        ReadOnlySpan<byte> nonce = associatedData[..NonceSize];
        CX.Derive(comKey, encKey, nonce, key);

        Span<byte> commitment = stackalloc byte[CommitmentSize];
        DaviesMeyer(commitment, ciphertext.Slice(CommitmentSize, BlockSize), comKey);

        bool valid = ConstantTime.Equals(ciphertext[..CommitmentSize], commitment);
        CryptographicOperations.ZeroMemory(commitment);

        if (!valid) {
            CryptographicOperations.ZeroMemory(comKey);
            CryptographicOperations.ZeroMemory(encKey);
            throw new CryptographicException();
        }

        Daence.Decrypt(plaintext, ciphertext[CommitmentSize..], subkeys, associatedData);
        CryptographicOperations.ZeroMemory(comKey);
        CryptographicOperations.ZeroMemory(encKey);
    }

    private static void DaviesMeyer(Span<byte> commitment, ReadOnlySpan<byte> ciphertextBlock, ReadOnlySpan<byte> comKey)
    {
        using var aes = Aes.Create();
        aes.Key = comKey.ToArray();
        aes.EncryptEcb(ciphertextBlock, commitment, PaddingMode.None);
        for (int i = 0; i < ciphertextBlock.Length; i++) {
            commitment[i] ^= ciphertextBlock[i];
        }
    }
}
