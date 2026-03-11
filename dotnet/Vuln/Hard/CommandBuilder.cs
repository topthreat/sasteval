namespace SastEval.Vuln.Hard;

/// <summary>
/// Helper class for CommandInjectionCrossFile - builds shell command with string concatenation.
/// </summary>
public static class CommandBuilder
{
    public static string BuildPingCommand(string target)
    {
        // VULNERABLE: User input concatenated into shell command
        return "ping -c 1 " + target;
    }
}
