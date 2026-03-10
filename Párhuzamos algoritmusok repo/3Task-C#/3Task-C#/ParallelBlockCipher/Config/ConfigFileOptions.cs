using ParallelBlockCipher.CLI;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ParallelBlockCipher.Config
{
    public static class ConfigFileOptions
    {
        public static CommandLineOptions Load(string path)
        {
            var json = System.IO.File.ReadAllText(path);
            var opts = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
            opts.Converters.Add(new JsonStringEnumConverter());
            return JsonSerializer.Deserialize<CommandLineOptions>(json, opts)!;
        }
    }
}
