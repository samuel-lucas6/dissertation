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
public class MisusePatches
{
    private byte[] ciphertext, plaintext, key, associatedData;

    // Different parameters to AEAD benchmarks because patch overhead is independent of message length
    [Params(1536)]
    public int PlaintextSize;

    // Offset from 12 since that's the nonce size to match AES-GCM-SIV
    [Params(12, 17, 28, 44, 76, 140, 268, 1036, 1548, 2060, 16396)]
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
    // RtC (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(RtC_Encrypt), nameof(RtC_Decrypt) })]
    public void RtC_Setup()
    {
        ciphertext = new byte[PlaintextSize + RtC.CommitmentSize + RtC.TagSize];
        plaintext = new byte[PlaintextSize];
        key = new byte[RtC.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        RtC.Encrypt(ciphertext, plaintext, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void RtC_Encrypt() => RtC.Encrypt(ciphertext, plaintext, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void RtC_Decrypt() => RtC.Decrypt(plaintext, ciphertext, key, associatedData);

    //
    // HtE[RtC] (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(HtE_RtC_Encrypt), nameof(HtE_RtC_Decrypt) })]
    public void HtE_RtC_Setup()
    {
        ciphertext = new byte[PlaintextSize + HtERtC.CommitmentSize + HtERtC.TagSize];
        plaintext = new byte[PlaintextSize];
        key = new byte[HtERtC.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        HtERtC.Encrypt(ciphertext, plaintext, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void HtE_RtC_Encrypt() => HtERtC.Encrypt(ciphertext, plaintext, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void HtE_RtC_Decrypt() => HtERtC.Decrypt(plaintext, ciphertext, key, associatedData);

    //
    // LibsodiumTransformMisuse (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(LibsodiumTransformMisuse_Encrypt), nameof(LibsodiumTransformMisuse_Decrypt) })]
    public void LibsodiumTransformMisuse_Setup()
    {
        ciphertext = new byte[PlaintextSize + LibsodiumTransformMisuse.CommitmentSize + LibsodiumTransformMisuse.TagSize];
        plaintext = new byte[PlaintextSize];
        key = new byte[LibsodiumTransformMisuse.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        LibsodiumTransformMisuse.Encrypt(ciphertext, plaintext, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void LibsodiumTransformMisuse_Encrypt() => LibsodiumTransformMisuse.Encrypt(ciphertext, plaintext, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void LibsodiumTransformMisuse_Decrypt() => LibsodiumTransformMisuse.Decrypt(plaintext, ciphertext, key, associatedData);

    //
    // DEH (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(DEH_Encrypt), nameof(DEH_Decrypt) })]
    public void DEH_Setup()
    {
        ciphertext = new byte[PlaintextSize + DEH.CommitmentSize + DEH.TagSize];
        plaintext = new byte[PlaintextSize];
        key = new byte[DEH.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        DEH.Encrypt(ciphertext, plaintext, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void DEH_Encrypt() => DEH.Encrypt(ciphertext, plaintext, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void DEH_Decrypt() => DEH.Decrypt(plaintext, ciphertext, key, associatedData);
}
