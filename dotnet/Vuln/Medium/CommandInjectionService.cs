using System.Diagnostics;

namespace SastEval.Vuln.Medium;

/// <summary>
/// CWE-78: OS Command Injection - User input flows through helper method to Process.Start.
/// </summary>
public static class CommandInjectionService
{
    private static string RunCommand(string userInput)
    {
        // VULNERABLE: User input concatenated into shell command via cross-method flow
        var process = Process.Start(new ProcessStartInfo
        {
            FileName = "/bin/sh",
            Arguments = "-c ls " + userInput,
            RedirectStandardOutput = true,
            UseShellExecute = false
        });

        return process?.StandardOutput.ReadToEnd() ?? "No output";
    }

    public static IResult Handle(HttpContext context)
    {
        var dir = context.Request.Query["dir"].ToString();

        if (string.IsNullOrEmpty(dir))
        {
            return Results.BadRequest("Missing 'dir' query parameter");
        }

        var output = RunCommand(dir);
        return Results.Text(output);
    }
}
