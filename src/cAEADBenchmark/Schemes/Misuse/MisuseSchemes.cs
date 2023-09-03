using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using cAEAD;

namespace cAEADBenchmark;

[Config(typeof(Configuration))]
[RPlotExporter]
[CategoriesColumn]
// ByCategory required for Baseline = true
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class MisuseSchemes
{
    private byte[] ciphertext, plaintext, nonce, key, associatedData;

    // Same parameters as the AEAD benchmarks
    [Params(0, 16, 32, 64, 128, 256, 512, 1024, 1536, 2048, 16384, 32768, 65536, 131072, 524288, 1048576, 10485760, 52428800, 104857600)]
    public int PlaintextSize;

    [Params(0, 64, 1536, 16384)]
    public int AssociatedDataSize;

    //
    // Daence (AEAD)
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

    [BenchmarkCategory(Constants.Encryption), Benchmark(Baseline = true)]
    public void Daence_Encrypt() => Daence.Encrypt(ciphertext, plaintext, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark(Baseline = true)]
    public void Daence_Decrypt() => Daence.Decrypt(plaintext, ciphertext, key, associatedData);

    //
    // AEGIS-256-DFV4 (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(AEGIS256_DFV4_Encrypt), nameof(AEGIS256_DFV4_Decrypt) })]
    public void AEGIS256_DFV4_Setup()
    {
        ciphertext = new byte[PlaintextSize + AEGIS256DFV4.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[AEGIS256DFV4.NonceSize];
        key = new byte[AEGIS256DFV4.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        AEGIS256DFV4.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void AEGIS256_DFV4_Encrypt() => AEGIS256DFV4.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void AEGIS256_DFV4_Decrypt() => AEGIS256DFV4.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // AEGIS-256-SIV (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(AEGIS256_SIV_Encrypt), nameof(AEGIS256_SIV_Decrypt) })]
    public void AEGIS256_SIV_Setup()
    {
        ciphertext = new byte[PlaintextSize + AEGIS256SIV.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[AEGIS256SIV.NonceSize];
        key = new byte[AEGIS256SIV.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        AEGIS256SIV.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void AEGIS256_SIV_Encrypt() => AEGIS256SIV.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void AEGIS256_SIV_Decrypt() => AEGIS256SIV.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // cSIV with BLAKE3 (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(cSIVBLAKE3_Encrypt), nameof(cSIVBLAKE3_Decrypt) })]
    public void cSIVBLAKE3_Setup()
    {
        ciphertext = new byte[PlaintextSize + cSIVBLAKE3.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[cSIVBLAKE3.NonceSize];
        key = new byte[cSIVBLAKE3.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        cSIVBLAKE3.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void cSIVBLAKE3_Encrypt() => cSIVBLAKE3.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void cSIVBLAKE3_Decrypt() => cSIVBLAKE3.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // cSIV with BLAKE2b (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(cSIVBLAKE2b_Encrypt), nameof(cSIVBLAKE2b_Decrypt) })]
    public void cSIVBLAKE2b_Setup()
    {
        ciphertext = new byte[PlaintextSize + cSIVBLAKE2b.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[cSIVBLAKE2b.NonceSize];
        key = new byte[cSIVBLAKE2b.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        cSIVBLAKE2b.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void cSIVBLAKE2b_Encrypt() => cSIVBLAKE2b.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void cSIVBLAKE2b_Decrypt() => cSIVBLAKE2b.Decrypt(plaintext, ciphertext, nonce, key, associatedData);
}
