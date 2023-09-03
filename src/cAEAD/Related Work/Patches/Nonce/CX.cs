using System.Security.Cryptography;

namespace cAEAD;

// https://eprint.iacr.org/2022/268
public static class CX
{
    public const int BlockSize = 16;
    public const int MinCommitmentSize = BlockSize;
    public const int MaxCommitmentSize = BlockSize * 2;
    public const int MinSubkeySize = BlockSize;
    public const int MaxSubkeySize = BlockSize * 2;
    public const int MaxNonceSize = BlockSize - 1;
    public const int MinKeySize = BlockSize;
    public const int MaxKeySize = BlockSize * 2;

    public static void Derive(Span<byte> commitment, Span<byte> subkey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> key)
    {
        if (commitment.Length != MinCommitmentSize && commitment.Length != MaxCommitmentSize) { throw new ArgumentOutOfRangeException(nameof(commitment), commitment.Length, $"{nameof(commitment)} must be {MinCommitmentSize} or {MaxCommitmentSize} bytes long."); }
        if (subkey.Length != MinSubkeySize && subkey.Length != MaxSubkeySize) { throw new ArgumentOutOfRangeException(nameof(subkey), subkey.Length, $"{nameof(subkey)} must be {MinSubkeySize} or {MaxSubkeySize} bytes long."); }
        if (nonce.Length > MaxNonceSize) { throw new ArgumentOutOfRangeException(nameof(nonce), nonce.Length, $"{nameof(nonce)} must be less than {BlockSize} bytes long."); }
        if (key.Length != MinKeySize && key.Length != MaxKeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {MinKeySize} or {MaxKeySize} bytes long."); }

        int blockCount = commitment.Length / BlockSize + subkey.Length / BlockSize;
        Span<byte> blocks = stackalloc byte[BlockSize * blockCount];
        blocks.Clear();
        for (int i = 0; i < blockCount; i++) {
            Span<byte> block = blocks.Slice(i * BlockSize, BlockSize);
            nonce.CopyTo(block);
            block[^1] = (byte)(i + 1);
        }

        using var aes = Aes.Create();
        aes.Key = key.ToArray();
        Span<byte> ciphertext = stackalloc byte[blocks.Length];
        aes.EncryptEcb(blocks, ciphertext, PaddingMode.None);

        for (int i = 0; i < BlockSize; i++) {
            ciphertext[i] ^= blocks[i];
        }

        ciphertext[..commitment.Length].CopyTo(commitment);
        ciphertext[commitment.Length..].CopyTo(subkey);

        CryptographicOperations.ZeroMemory(blocks);
        CryptographicOperations.ZeroMemory(ciphertext);
    }
}
