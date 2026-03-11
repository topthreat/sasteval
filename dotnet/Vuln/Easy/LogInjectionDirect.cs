namespace SastEval.Vuln.Easy;

/// <summary>
/// CWE-117: Log Injection - User input written directly to log output without sanitization.
/// </summary>
public static class LogInjectionDirect
{
    public static IResult Handle(HttpContext context)
    {
        var username = context.Request.Query["username"].ToString();

        if (string.IsNullOrEmpty(username))
        {
            return Results.BadRequest("Missing 'username' query parameter");
        }

        // VULNERABLE: User input directly concatenated into log message (allows log forging)
        Console.WriteLine("Login attempt for: " + username);

        return Results.Text("Login attempt logged");
    }
}
