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
public class NoncePatches
{
    private byte[] ciphertext, plaintext, nonce, key, associatedData;

    // Different parameters to AEAD benchmarks because patch overhead is independent of message length
    [Params(1536)]
    public int PlaintextSize;

    [Params(0, 5, 16, 32, 64, 128, 256, 1024, 1536, 2048, 16384)]
    public int AssociatedDataSize;

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
    // ChaCha20 + Poly1305 (AEAD)
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

    //
    // AEAD-then-MAC (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(AEADThenMAC_Encrypt), nameof(AEADThenMAC_Decrypt) })]
    public void AEADThenMAC_Setup()
    {
        ciphertext = new byte[PlaintextSize + AEADThenMAC.TagSize + AEADThenMAC.CommitmentSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[AEADThenMAC.NonceSize];
        key = new byte[AEADThenMAC.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        AEADThenMAC.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void AEADThenMAC_Encrypt() => AEADThenMAC.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void AEADThenMAC_Decrypt() => AEADThenMAC.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // Fixed-string MAC (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(FixedStringMAC_Encrypt), nameof(FixedStringMAC_Decrypt) })]
    public void FixedStringMAC_Setup()
    {
        ciphertext = new byte[PlaintextSize + FixedStringMAC.TagSize + FixedStringMAC.CommitmentSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[FixedStringMAC.NonceSize];
        key = new byte[FixedStringMAC.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        FixedStringMAC.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void FixedStringMAC_Encrypt() => FixedStringMAC.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void FixedStringMAC_Decrypt() => FixedStringMAC.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // Padding Fix (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(PaddingFix_Encrypt), nameof(PaddingFix_Decrypt) })]
    public void PaddingFix_Setup()
    {
        ciphertext = new byte[PlaintextSize + PaddingFix.CommitmentSize + PaddingFix.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[PaddingFix.NonceSize];
        key = new byte[PaddingFix.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        PaddingFix.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void PaddingFix_Encrypt() => PaddingFix.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void PaddingFix_Decrypt() => PaddingFix.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // Non-library Padding Fix (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(PaddingFixNonLibrary_Encrypt), nameof(PaddingFixNonLibrary_Decrypt) })]
    public void PaddingFixNonLibrary_Setup()
    {
        ciphertext = new byte[PlaintextSize + PaddingFix.CommitmentSize + PaddingFix.TagSize];
        plaintext = new byte[PlaintextSize + PaddingFix.CommitmentSize];
        nonce = new byte[PaddingFix.NonceSize];
        key = new byte[PaddingFix.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext.AsSpan()[PaddingFix.CommitmentSize..]);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        ChaCha20Poly1305.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void PaddingFixNonLibrary_Encrypt() => ChaCha20Poly1305.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void PaddingFixNonLibrary_Decrypt()
    {
        ChaCha20Poly1305.Decrypt(plaintext, ciphertext, nonce, key, associatedData);
        if (!ConstantTime.IsAllZeros(plaintext.AsSpan()[..PaddingFix.CommitmentSize])) {
            throw new CryptographicException();
        }
    }

    //
    // CommitKeyI (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(CommitKeyI_Encrypt), nameof(CommitKeyI_Decrypt) })]
    public void CommitKeyI_Setup()
    {
        ciphertext = new byte[PlaintextSize + CommitKey.CommitmentSize + CommitKey.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[CommitKey.NonceSize];
        key = new byte[CommitKey.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        CommitKey.Encrypt(ciphertext, plaintext, nonce, key, associatedData, CommitKey.Type.I);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void CommitKeyI_Encrypt() => CommitKey.Encrypt(ciphertext, plaintext, nonce, key, associatedData, CommitKey.Type.I);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void CommitKeyI_Decrypt() => CommitKey.Decrypt(plaintext, ciphertext, nonce, key, associatedData, CommitKey.Type.I);

    //
    // CommitKeyII (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(CommitKeyII_Encrypt), nameof(CommitKeyII_Decrypt) })]
    public void CommitKeyII_Setup()
    {
        ciphertext = new byte[PlaintextSize + CommitKey.CommitmentSize + CommitKey.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[CommitKey.NonceSize];
        key = new byte[CommitKey.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        CommitKey.Encrypt(ciphertext, plaintext, nonce, key, associatedData, CommitKey.Type.II);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void CommitKeyII_Encrypt() => CommitKey.Encrypt(ciphertext, plaintext, nonce, key, associatedData, CommitKey.Type.II);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void CommitKeyII_Decrypt() => CommitKey.Decrypt(plaintext, ciphertext, nonce, key, associatedData, CommitKey.Type.II);

    //
    // CommitKeyIII (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(CommitKeyIII_Encrypt), nameof(CommitKeyIII_Decrypt) })]
    public void CommitKeyIII_Setup()
    {
        ciphertext = new byte[PlaintextSize + CommitKey.CommitmentSize + CommitKey.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[CommitKey.NonceSize];
        key = new byte[CommitKey.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        CommitKey.Encrypt(ciphertext, plaintext, nonce, key, associatedData, CommitKey.Type.III);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void CommitKeyIII_Encrypt() => CommitKey.Encrypt(ciphertext, plaintext, nonce, key, associatedData, CommitKey.Type.III);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void CommitKeyIII_Decrypt() => CommitKey.Decrypt(plaintext, ciphertext, nonce, key, associatedData, CommitKey.Type.III);

    //
    // CommitKeyIV (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(CommitKeyIV_Encrypt), nameof(CommitKeyIV_Decrypt) })]
    public void CommitKeyIV_Setup()
    {
        ciphertext = new byte[PlaintextSize + CommitKey.CommitmentSize + CommitKey.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[CommitKey.NonceSize];
        key = new byte[CommitKey.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        CommitKey.Encrypt(ciphertext, plaintext, nonce, key, associatedData, CommitKey.Type.IV);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void CommitKeyIV_Encrypt() => CommitKey.Encrypt(ciphertext, plaintext, nonce, key, associatedData, CommitKey.Type.IV);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void CommitKeyIV_Decrypt() => CommitKey.Decrypt(plaintext, ciphertext, nonce, key, associatedData, CommitKey.Type.IV);

    //
    // VaillantTransform (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(VaillantTransform_Encrypt), nameof(VaillantTransform_Decrypt) })]
    public void VaillantTransform_Setup()
    {
        ciphertext = new byte[PlaintextSize + VaillantTransform.CommitmentSize + VaillantTransform.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[VaillantTransform.NonceSize];
        key = new byte[VaillantTransform.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        VaillantTransform.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void VaillantTransform_Encrypt() => VaillantTransform.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void VaillantTransform_Decrypt() => VaillantTransform.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // UtC (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(UtC_Encrypt), nameof(UtC_Decrypt) })]
    public void UtC_Setup()
    {
        ciphertext = new byte[PlaintextSize + UtC.CommitmentSize + UtC.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[UtC.NonceSize];
        key = new byte[UtC.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        UtC.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void UtC_Encrypt() => UtC.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void UtC_Decrypt() => UtC.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // HtE[UtC] (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(HtE_UtC_Encrypt), nameof(HtE_UtC_Decrypt) })]
    public void HtE_UtC_Setup()
    {
        ciphertext = new byte[PlaintextSize + HtEUtC.CommitmentSize + HtEUtC.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[HtEUtC.NonceSize];
        key = new byte[HtEUtC.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        HtEUtC.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void HtE_UtC_Encrypt() => HtEUtC.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void HtE_UtC_Decrypt() => HtEUtC.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // CTX (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(CTX_Encrypt), nameof(CTX_Decrypt) })]
    public void CTX_Setup()
    {
        ciphertext = new byte[PlaintextSize + CTX.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[CTX.NonceSize];
        key = new byte[CTX.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        CTX.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void CTX_Encrypt() => CTX.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void CTX_Decrypt() => CTX.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // LibsodiumTransform (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(LibsodiumTransform_Encrypt), nameof(LibsodiumTransform_Decrypt) })]
    public void LibsodiumTransform_Setup()
    {
        ciphertext = new byte[PlaintextSize + LibsodiumTransform.CommitmentSize + LibsodiumTransform.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[LibsodiumTransform.NonceSize];
        key = new byte[LibsodiumTransform.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        LibsodiumTransform.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void LibsodiumTransform_Encrypt() => LibsodiumTransform.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void LibsodiumTransform_Decrypt() => LibsodiumTransform.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // ContextHashing (Paper)
    //

    [GlobalSetup(Targets = new[] { nameof(ContextHashing_Encrypt), nameof(ContextHashing_Decrypt) })]
    public void ContextHashing_Setup()
    {
        ciphertext = new byte[PlaintextSize + ContextHashing.CommitmentSize + ContextHashing.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[ContextHashing.NonceSize];
        key = new byte[ContextHashing.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        ContextHashing.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void ContextHashing_Encrypt() => ContextHashing.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void ContextHashing_Decrypt() => ContextHashing.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // CCP-C1 with HChaCha20 (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(CCPC1HChaCha_Encrypt), nameof(CCPC1HChaCha_Decrypt) })]
    public void CCPC1HChaCha_Setup()
    {
        ciphertext = new byte[PlaintextSize + CCPC1HChaCha.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[CCPC1HChaCha.NonceSize];
        key = new byte[CCPC1HChaCha.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        CCPC1HChaCha.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void CCPC1HChaCha_Encrypt() => CCPC1HChaCha.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void CCPC1HChaCha_Decrypt() => CCPC1HChaCha.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // CCP-C1 with ChaChaMAC128 (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(CCPC1ChaChaMAC128_Encrypt), nameof(CCPC1ChaChaMAC128_Decrypt) })]
    public void CCPC1ChaChaMAC128_Setup()
    {
        ciphertext = new byte[PlaintextSize + CCPC1ChaChaMAC128.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[CCPC1ChaChaMAC128.NonceSize];
        key = new byte[CCPC1ChaChaMAC128.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        CCPC1ChaChaMAC128.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void CCPC1ChaChaMAC128_Encrypt() => CCPC1ChaChaMAC128.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void CCPC1ChaChaMAC128_Decrypt() => CCPC1ChaChaMAC128.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // CCP-C1 with ChaChaMAC256 (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(CCPC1ChaChaMAC256_Encrypt), nameof(CCPC1ChaChaMAC256_Decrypt) })]
    public void CCPC1ChaChaMAC256_Setup()
    {
        ciphertext = new byte[PlaintextSize + CCPC1ChaChaMAC256.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[CCPC1ChaChaMAC256.NonceSize];
        key = new byte[CCPC1ChaChaMAC256.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        CCPC1ChaChaMAC256.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void CCPC1ChaChaMAC256_Encrypt() => CCPC1ChaChaMAC256.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void CCPC1ChaChaMAC256_Decrypt() => CCPC1ChaChaMAC256.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // DtC (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(DtC_Encrypt), nameof(DtC_Decrypt) })]
    public void DtC_Setup()
    {
        ciphertext = new byte[PlaintextSize + DtC.CommitmentSize + DtC.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[DtC.NonceSize];
        key = new byte[DtC.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        DtC.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void DtC_Encrypt() => DtC.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void DtC_Decrypt() => DtC.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // CommitAll (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(CommitAll_Encrypt), nameof(CommitAll_Decrypt) })]
    public void CommitAll_Setup()
    {
        ciphertext = new byte[PlaintextSize + CommitAll.CommitmentSize + CommitAll.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[CommitAll.NonceSize];
        key = new byte[CommitAll.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        CommitAll.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void CommitAll_Encrypt() => CommitAll.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void CommitAll_Decrypt() => CommitAll.Decrypt(plaintext, ciphertext, nonce, key, associatedData);

    //
    // CTX+ (Proposal)
    //

    [GlobalSetup(Targets = new[] { nameof(CTXPlus_Encrypt), nameof(CTXPlus_Decrypt) })]
    public void CTXPlus_Setup()
    {
        ciphertext = new byte[PlaintextSize + CTXPlus.TagSize];
        plaintext = new byte[PlaintextSize];
        nonce = new byte[CTXPlus.NonceSize];
        key = new byte[CTXPlus.KeySize];
        associatedData = new byte[AssociatedDataSize];

        RandomNumberGenerator.Fill(plaintext);
        RandomNumberGenerator.Fill(nonce);
        RandomNumberGenerator.Fill(key);
        RandomNumberGenerator.Fill(associatedData);

        CTXPlus.Encrypt(ciphertext, plaintext, nonce, key, associatedData);
    }

    [BenchmarkCategory(Constants.Encryption), Benchmark]
    public void CTXPlus_Encrypt() => CTXPlus.Encrypt(ciphertext, plaintext, nonce, key, associatedData);

    [BenchmarkCategory(Constants.Decryption), Benchmark]
    public void CTXPlus_Decrypt() => CTXPlus.Decrypt(plaintext, ciphertext, nonce, key, associatedData);
}
