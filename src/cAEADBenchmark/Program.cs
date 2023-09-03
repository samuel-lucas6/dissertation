using BenchmarkDotNet.Running;

namespace cAEADBenchmark;

public class Program
{
    public static void Main(string[] args)
    {
        // Uncomment the benchmark to run
        //var aeads = BenchmarkRunner.Run<AEADs>();
        //var noncePatches = BenchmarkRunner.Run<NoncePatches>();
        //var misusePatches = BenchmarkRunner.Run<MisusePatches>();
        var nonceSchemes = BenchmarkRunner.Run<NonceSchemes>();
        //var misuseSchemes = BenchmarkRunner.Run<MisuseSchemes>();
    }
}
