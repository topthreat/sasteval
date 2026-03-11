using System.Diagnostics;

namespace SastEval.Vuln.Hard;

/// <summary>
/// Helper class for CommandInjectionCrossFile - executes shell command.
/// </summary>
public static class CommandRunner
{
    public static string Run(string cmd)
    {
        // VULNERABLE: Executes arbitrary shell command built from user input
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = "/bin/sh",
            Arguments = "-c " + cmd,
            RedirectStandardOutput = true,
            UseShellExecute = false
        });

        return process?.StandardOutput.ReadToEnd() ?? "No output";
    }
}
