using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using ParallelBlockCipher.CLI;
using ParallelBlockCipher.Config;
using ParallelBlockCipher.Core;
using ParallelBlockCipher.Crypto;
using ParallelBlockCipher.IO;
using ParallelBlockCipher.Strategies;

namespace ParallelBlockCipher
{
    class Program
    {
        static int Main(string[] args)
        {
            try
            {
                var opt = LoadOptions(args);
                var decrypt = string.Equals(opt.Mode, "decrypt", StringComparison.OrdinalIgnoreCase);
                Console.WriteLine(decrypt ? "Decrypting..." : "Encrypting...");
                var cipher = new AesLikeCipher();
                var key = KeyDerivation.DeriveKey(opt.Password, Encoding.UTF8.GetBytes("ParallelBlockCipherSalt"));
                var inputBytes = File.ReadAllBytes(opt.InputFile);
                var blocks = FileSplitter.Split(inputBytes, cipher.BlockSizeBytes, pad: !decrypt);
                var chosen = CreateStrategy(opt.Strategy, opt.Threads);
                double parTime = RunStrategy(chosen, blocks, key, cipher, decrypt, out var outputBytes);
                if (decrypt) outputBytes = Padding.Unpad(outputBytes, cipher.BlockSizeBytes);
                File.WriteAllBytes(opt.OutputFile, outputBytes);
                Console.WriteLine("Parallel finished.");
                double refTime = parTime;
                if (opt.Strategy != StrategyType.SingleThreaded)
                {
                    Console.WriteLine("Running reference single-threaded pass...");
                    refTime = RunStrategy(new SingleThreadedStrategy(), blocks, key, cipher, decrypt, out _);
                    Console.WriteLine("Reference finished.");
                }
                ReportStats(inputBytes.Length, parTime, refTime, opt);
                Console.WriteLine("Done.");
                Console.ReadLine();
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                return 1;
            }
        }

        private static double RunStrategy(IEncryptionStrategy strategy,
                                          byte[][] blocks,
                                          byte[] key,
                                          IBlockCipher cipher,
                                          bool decrypt,
                                          out byte[] result)
        {
            var sw = Stopwatch.StartNew();
            var processed = strategy.Process(blocks, key, cipher, decrypt, null).ToArray();
            result = FileAssembler.Combine(processed);
            sw.Stop();
            return sw.Elapsed.TotalSeconds;
        }

        private static void ReportStats(long bytes, double parTime, double refTime, CommandLineOptions opt)
        {
            double mb = bytes / 1048576.0;
            double parThroughput = mb / parTime;
            double refThroughput = mb / refTime;
            Console.WriteLine($"Size              : {mb:F2} MB");
            Console.WriteLine($"Parallel time     : {parTime:F3} s  ({parThroughput:F2} MB/s)");
            if (opt.Strategy != StrategyType.SingleThreaded)
            {
                Console.WriteLine($"Single-thread time: {refTime:F3} s  ({refThroughput:F2} MB/s)");
                var speedup = refTime / parTime;
                var threads = opt.Threads > 0 ? opt.Threads : Environment.ProcessorCount;
                Console.WriteLine($"Speed-up          : {speedup:F2}×");
                Console.WriteLine($"Efficiency/thread : {speedup / threads:F2}");
            }
        }

        private static CommandLineOptions LoadOptions(string[] args)
        {
            if (args.Length == 0 && File.Exists("config.json"))
                return ConfigFileOptions.Load("config.json");
            if (args.Length == 1 && !args[0].StartsWith("--") && args[0].EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                return ConfigFileOptions.Load(args[0]);
            if (args.Length >= 2 && string.Equals(args[0], "--config", StringComparison.OrdinalIgnoreCase))
                return ConfigFileOptions.Load(args[1]);
            return CommandLineOptions.Parse(args);
        }

        private static IEncryptionStrategy CreateStrategy(StrategyType t, int threads) => t switch
        {
            StrategyType.SingleThreaded => new SingleThreadedStrategy(),
            StrategyType.ParallelFor => new ParallelForStrategy(threads),
            StrategyType.TaskBased => new TaskBasedStrategy(threads),
            StrategyType.AsyncAwait => new AsyncStrategy(threads),
            _ => new SingleThreadedStrategy()
        };
    }
}
