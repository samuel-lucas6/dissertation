using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using cAEAD;
using Geralt;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace cAEADBenchmark;

[Config(typeof(Configuration))]
[RPlotExporter]
[CategoriesColumn]
// ByCategory required for Baseline = true
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class AEADs
{
    private byte[] ciphertext, plaintext, nonce, key, associatedData, tag;

    [Params(0, 16, 32, 64, 128, 256, 512, 1024, 1536, 2048, 16384, 32768, 65536, 131072, 524288, 1048576, 10485760, 52428800, 104857600)]
    public int PlaintextSize;

    [Params(0, 64, 1536, 16384)]
    public int AssociatedDataSize;

    //
    // ChaCha20-Poly1305
    //

    [GlobalSetup(Targets = new[] { nameof(ChaCha20Poly1305_Encrypt), nameof(ChaCha20Poly1305_Decrypt) })]
    public void ChaCha20Poly1305_Setup()
    {
        ciphertext = new byte[PlaintextSize + ChaCha20Poly1305.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[ChaCha20Poly1305.NonceSize];
        key = new byte[ChaCha20Poly1305.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        ChaCha20Poly1305.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark(Baseline = true)]
    public void ChaCha20Poly1305_Encrypt() => ChaCha20Poly1305.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark(Baseline = true)]
    public void ChaCha20Poly1305_Decrypt() => ChaCha20Poly1305.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    /*//
    // ChaCha20 + Poly1305
    //

    [GlobalSetup(Targets = new[] { nameof(ChaChaPoly_Encrypt), nameof(ChaChaPoly_Decrypt) })]
    public void ChaChaPoly_Setup()
    {
        ciphertext = new byte[PlaintextSize + ChaChaPoly.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[ChaChaPoly.NonceSize];
        key = new byte[ChaChaPoly.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        ChaChaPoly.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void ChaChaPoly_Encrypt() => ChaChaPoly.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void ChaChaPoly_Decrypt() => ChaChaPoly.Decrypt(plaintext, ciphertext, nonce, key, associatedData);
    */

    //
    // XChaCha20-Poly1305
    //

    [GlobalSetup(Targets = new[] { nameof(XChaCha20Poly1305_Encrypt), nameof(XChaCha20Poly1305_Decrypt) })]
    public void XChaCha20Poly1305_Setup()
    {
        ciphertext = new byte[PlaintextSize + XChaCha20Poly1305.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[XChaCha20Poly1305.NonceSize];
        key = new byte[XChaCha20Poly1305.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        XChaCha20Poly1305.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void XChaCha20Poly1305_Encrypt() => XChaCha20Poly1305.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void XChaCha20Poly1305_Decrypt() => XChaCha20Poly1305.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // Daence
    //

    [GlobalSetup(Targets = new[] { nameof(Daence_Encrypt), nameof(Daence_Decrypt) })]
    public void Daence_Setup()
    {
        ciphertext = new byte[PlaintextSize + Daence.TagSize];
        plaintext = new byte[PlaintextSize];
        key = new byte[Daence.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        Daence.Encrypt(ciphertext, plaintext, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void Daence_Encrypt() => Daence.Encrypt(ciphertext, plaintext, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void Daence_Decrypt() => Daence.Decrypt(plaintext, ciphertext, key, associatedData);

    //
    // AES-GCM
    //

    [GlobalSetup(Targets = new[] { nameof(AesGCM_Encrypt), nameof(AesGCM_Decrypt) })]
    public void AesGCM_Setup()
    {
        tag = new byte[ChaCha20Poly1305.TagSize];
        ciphertext = new byte[PlaintextSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[ChaCha20Poly1305.NonceSize];
        key = new byte[ChaCha20Poly1305.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        using var aes = new AesGcm(key);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void AesGCM_Encrypt()
    {
        using var aes = new AesGcm(key);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
    }

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void AesGCM_Decrypt()
    {
        using var aes = new AesGcm(key);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
    }

    //
    // AES-CCM
    //

    [GlobalSetup(Targets = new[] { nameof(AesCCM_Encrypt), nameof(AesCCM_Decrypt) })]
    public void AesCCM_Setup()
    {
        tag = new byte[ChaCha20Poly1305.TagSize];
        ciphertext = new byte[PlaintextSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[ChaCha20Poly1305.NonceSize];
        key = new byte[ChaCha20Poly1305.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        using var aes = new AesCcm(key);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void AesCCM_Encrypt()
    {
        using var aes = new AesCcm(key);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
    }

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void AesCCM_Decrypt()
    {
        using var aes = new AesCcm(key);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
    }

    //
    // AEGIS-256
    //

    [GlobalSetup(Targets = new[] { nameof(AEGIS256_Encrypt), nameof(AEGIS256_Decrypt) })]
    public void AEGIS256_Setup()
    {
        ciphertext = new byte[PlaintextSize + AEGIS256.MaxTagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[AEGIS256.NonceSize];
        key = new byte[AEGIS256.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        AEGIS256.Encrypt(ciphertext, plaintext, nonce, key, associatedData, AEGIS256.MaxTagSize);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void AEGIS256_Encrypt() => AEGIS256.Encrypt(ciphertext, plaintext, nonce, key, associatedData, AEGIS256.MaxTagSize);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void AEGIS256_Decrypt() => AEGIS256.Decrypt(plaintext, ciphertext, nonce, key, associatedData, AEGIS256.MaxTagSize);

    //
    // Rocca-S
    //

    [GlobalSetup(Targets = new[] { nameof(RoccaS_Encrypt), nameof(RoccaS_Decrypt) })]
    public void RoccaS_Setup()
    {
        ciphertext = new byte[PlaintextSize + RoccaS.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[RoccaS.NonceSize];
        key = new byte[RoccaS.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        RoccaS.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void RoccaS_Encrypt() => RoccaS.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void RoccaS_Decrypt() => RoccaS.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // Ascon-80pq
    //

    [GlobalSetup(Targets = new[] { nameof(Ascon80pq_Encrypt), nameof(Ascon80pq_Decrypt) })]
    public void Ascon80pq_Setup()
    {
        ciphertext = new byte[PlaintextSize + Ascon80pq.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[Ascon80pq.NonceSize];
        key = new byte[Ascon80pq.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        Ascon80pq.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void Ascon80pq_Encrypt() => Ascon80pq.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void Ascon80pq_Decrypt() => Ascon80pq.Decrypt(plaintext, ciphertext, nonce, key, associatedData);
}
