namespace cAEAD;

public sealed class AEGIS256Mac : IDisposable
{
    public const int KeySize = AEGIS256.KeySize;
    public const int MaxTagSize = AEGIS256.MaxTagSize;
    public const int MinTagSize = AEGIS256.MinTagSize;
    private bool _x86;

    public AEGIS256Mac(ReadOnlySpan<byte> key)
    {
        Initialize(key);
    }

    private void Initialize(ReadOnlySpan<byte> key)
    {
        if (key.Length != KeySize) { throw new ArgumentOutOfRangeException(nameof(key), key.Length, $"{nameof(key)} must be {KeySize} bytes long."); }

        if (AEGIS256MacX86.IsSupported()) {
            _x86 = true;
            AEGIS256MacX86.Initialize(key);
        }
        else if (AEGIS256MacArm.IsSupported()) {
            _x86 = false;
            AEGIS256MacArm.Initialize(key);
        }
        else {
            throw new PlatformNotSupportedException();
        }
    }

    public void Update(ReadOnlySpan<byte> message)
    {
        if (_x86) {
            AEGIS256MacX86.Update(message);
        }
        else {
            AEGIS256MacArm.Update(message);
        }
    }

    public void Finalize(Span<byte> tag)
    {
        if (tag.Length != MaxTagSize && tag.Length != MinTagSize) { throw new ArgumentOutOfRangeException(nameof(tag), tag.Length, $"{nameof(tag)} must be {MinTagSize} or {MaxTagSize} bytes long."); }

        if (_x86) {
            AEGIS256MacX86.Finalize(tag);
        }
        else {
            AEGIS256MacArm.Finalize(tag);
        }
    }

    public void Dispose()
    {
        if (_x86) {
            AEGIS256MacX86.ZeroState();
        }
        else {
            AEGIS256MacArm.ZeroState();
        }
    }
}
