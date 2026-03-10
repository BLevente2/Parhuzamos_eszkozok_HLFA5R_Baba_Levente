// CLI/CommandLineOptions.cs
using System;
using ParallelBlockCipher.Core;

namespace ParallelBlockCipher.CLI
{
    public class CommandLineOptions
    {
        public string Mode { get; set; }
        public string InputFile { get; set; }
        public string OutputFile { get; set; }
        public string Password { get; set; }
        public StrategyType Strategy { get; set; } = StrategyType.SingleThreaded;
        public int Threads { get; set; } = 0;

        public static CommandLineOptions Parse(string[] args)
        {
            var opts = new CommandLineOptions();
            for (var i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--mode":
                        opts.Mode = args[++i];
                        break;
                    case "--input":
                        opts.InputFile = args[++i];
                        break;
                    case "--output":
                        opts.OutputFile = args[++i];
                        break;
                    case "--password":
                        opts.Password = args[++i];
                        break;
                    case "--strategy":
                        opts.Strategy = Enum.Parse<StrategyType>(args[++i], true);
                        break;
                    case "--threads":
                        opts.Threads = int.Parse(args[++i]);
                        break;
                    default:
                        throw new ArgumentException($"Unknown argument: {args[i]}");
                }
            }

            if (string.IsNullOrEmpty(opts.Mode)
                || string.IsNullOrEmpty(opts.InputFile)
                || string.IsNullOrEmpty(opts.OutputFile)
                || string.IsNullOrEmpty(opts.Password))
            {
                throw new ArgumentException("Required arguments: --mode, --input, --output, --password");
            }

            return opts;
        }
    }
}
