using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using cAEAD;
using ChaCha20Poly1305 = Geralt.ChaCha20Poly1305;

namespace cAEADBenchmark;

[Config(typeof(Configuration))]
[RPlotExporter]
[CategoriesColumn]
// ByCategory required for Baseline = true
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class NonceSchemes
{
    private byte[] ciphertext, plaintext, nonce, key, associatedData;

    // Same parameters as the AEAD benchmarks
    [Params(0, 16, 32, 64, 128, 256, 512, 1024, 1536, 2048, 16384, 32768, 65536, 131072, 524288, 1048576, 10485760, 52428800, 104857600)]
    public int PlaintextSize;

    [Params(0, 64, 1536, 16384)]
    public int AssociatedDataSize;

    /*
    //
    // ChaCha20-Poly1305 (AEAD)
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

    //
    // cEtM with BLAKE3 (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(cEtMBLAKE3_Encrypt), nameof(cEtMBLAKE3_Decrypt) })]
    public void cEtMBLAKE3_Setup()
    {
        ciphertext = new byte[PlaintextSize + cEtMBLAKE3.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[cEtMBLAKE3.NonceSize];
        key = new byte[cEtMBLAKE3.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        cEtMBLAKE3.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void cEtMBLAKE3_Encrypt() => cEtMBLAKE3.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void cEtMBLAKE3_Decrypt() => cEtMBLAKE3.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // cEtM with BLAKE2b (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(cEtMBLAKE2b_Encrypt), nameof(cEtMBLAKE2b_Decrypt) })]
    public void cEtMBLAKE2b_Setup()
    {
        ciphertext = new byte[PlaintextSize + cEtMBLAKE2b.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[cEtMBLAKE2b.NonceSize];
        key = new byte[cEtMBLAKE2b.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        cEtMBLAKE2b.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void cEtMBLAKE2b_Encrypt() => cEtMBLAKE2b.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void cEtMBLAKE2b_Decrypt() => cEtMBLAKE2b.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // oEtM with BLAKE3 (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(oEtMBLAKE3_Encrypt), nameof(oEtMBLAKE3_Decrypt) })]
    public void oEtMBLAKE3_Setup()
    {
        ciphertext = new byte[PlaintextSize + oEtMBLAKE3.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[oEtMBLAKE3.NonceSize];
        key = new byte[oEtMBLAKE3.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        oEtMBLAKE3.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void oEtMBLAKE3_Encrypt() => oEtMBLAKE3.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void oEtMBLAKE3_Decrypt() => oEtMBLAKE3.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // oEtM with BLAKE2b (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(oEtMBLAKE2b_Encrypt), nameof(oEtMBLAKE2b_Decrypt) })]
    public void oEtMBLAKE2b_Setup()
    {
        ciphertext = new byte[PlaintextSize + oEtMBLAKE2b.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[oEtMBLAKE2b.NonceSize];
        key = new byte[oEtMBLAKE2b.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        oEtMBLAKE2b.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void oEtMBLAKE2b_Encrypt() => oEtMBLAKE2b.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void oEtMBLAKE2b_Decrypt() => oEtMBLAKE2b.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // Ascon-80pqc (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(Ascon80pqc_Encrypt), nameof(Ascon80pqc_Decrypt) })]
    public void Ascon80pqc_Setup()
    {
        ciphertext = new byte[PlaintextSize + Ascon80pqc.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[Ascon80pqc.NonceSize];
        key = new byte[Ascon80pqc.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        Ascon80pqc.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void Ascon80pqc_Encrypt() => Ascon80pqc.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void Ascon80pqc_Decrypt() => Ascon80pqc.Decrypt(plaintext, ciphertext, nonce, key, associatedData);
    */

    //
    // Ascon-128pqc (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(Ascon128pqc_Encrypt), nameof(Ascon128pqc_Decrypt) })]
    public void Ascon128pqc_Setup()
    {
        ciphertext = new byte[PlaintextSize + Ascon128pqc.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[Ascon128pqc.NonceSize];
        key = new byte[Ascon128pqc.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        Ascon128pqc.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void Ascon128pqc_Encrypt() => Ascon128pqc.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void Ascon128pqc_Decrypt() => Ascon128pqc.Decrypt(plaintext, ciphertext, nonce, key, associatedData);
}
