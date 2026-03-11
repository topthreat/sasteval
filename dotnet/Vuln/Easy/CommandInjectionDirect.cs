using System.Diagnostics;

namespace SastEval.Vuln.Easy;

/// <summary>
/// CWE-78: OS Command Injection - User input passed directly to Process.Start.
/// </summary>
public static class CommandInjectionDirect
{
    public static IResult Handle(HttpContext context)
    {
        var host = context.Request.Query["host"].ToString();

        if (string.IsNullOrEmpty(host))
        {
            return Results.BadRequest("Missing 'host' query parameter");
        }

        // VULNERABLE: Direct concatenation of user input into OS command
        var process = Process.Start("cmd.exe", "/c ping " + host);
        process?.WaitForExit();

        return Results.Text($"Ping executed for host: {host}");
    }
}
