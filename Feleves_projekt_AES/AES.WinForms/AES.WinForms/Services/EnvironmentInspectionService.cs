using System.Runtime.InteropServices;
using AES.WinForms.Native;

namespace AES.WinForms.Services;

public sealed class EnvironmentInspectionService
{
    private readonly NativeCryptoFacade _nativeCryptoFacade;

    public EnvironmentInspectionService(NativeCryptoFacade nativeCryptoFacade)
    {
        _nativeCryptoFacade = nativeCryptoFacade;
    }

    public string BuildDiagnosticsReport()
    {
        var lines = new List<string>
        {
            $"Framework: {RuntimeInformation.FrameworkDescription}",
            $"OS: {RuntimeInformation.OSDescription}",
            $"Architecture: {RuntimeInformation.ProcessArchitecture}",
            $"Logical processors: {Environment.ProcessorCount}",
            $"Application base directory: {AppContext.BaseDirectory}",
            $"crypto_aes.dll present: {File.Exists(Path.Combine(AppContext.BaseDirectory, "crypto_aes.dll"))}",
            $"crypto_aes_opencl.dll present: {File.Exists(Path.Combine(AppContext.BaseDirectory, "crypto_aes_opencl.dll"))}",
            $"kernel_loader.dll present: {File.Exists(Path.Combine(AppContext.BaseDirectory, "kernel_loader.dll"))}",
            $"kernels folder present: {Directory.Exists(Path.Combine(AppContext.BaseDirectory, "kernels"))}"
        };

        if (_nativeCryptoFacade.TryWarmupOpenCl(out var warmupMessage))
        {
            lines.Add(warmupMessage);
        }
        else
        {
            lines.Add(warmupMessage);
            lines.Add($"OpenCL details: {_nativeCryptoFacade.GetOpenClLastErrorMessage()}");
        }

        return string.Join(Environment.NewLine, lines);
    }
}
