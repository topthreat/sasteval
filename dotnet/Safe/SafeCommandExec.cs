using System.Diagnostics;

namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-78: Hardcoded command with no user input.
/// SAST tools should NOT flag this as command injection.
/// </summary>
public static class SafeCommandExec
{
    public static IResult Handle(HttpContext context)
    {
        // SAFE: Hardcoded command and argument with no user input
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = "ls",
            Arguments = "/tmp",
            RedirectStandardOutput = true,
            UseShellExecute = false
        });

        var output = process?.StandardOutput.ReadToEnd() ?? "No output";
        return Results.Text(output);
    }
}
