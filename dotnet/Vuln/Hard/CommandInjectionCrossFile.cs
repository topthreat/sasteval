namespace SastEval.Vuln.Hard;

/// <summary>
/// CWE-78: OS Command Injection - Three-class taint chain: Handler -> CommandBuilder -> CommandRunner.
/// </summary>
public static class CommandInjectionCrossFile
{
    public static IResult Handle(HttpContext context)
    {
        var target = context.Request.Query["target"].ToString();

        if (string.IsNullOrEmpty(target))
        {
            return Results.BadRequest("Missing 'target' query parameter");
        }

        // VULNERABLE: User input flows across three classes without sanitization
        var cmd = CommandBuilder.BuildPingCommand(target);
        var output = CommandRunner.Run(cmd);

        return Results.Text(output);
    }
}
