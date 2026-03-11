namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-117: User input sanitized before logging.
/// SAST tools should NOT flag this as log injection.
/// </summary>
public static class SafeLogging
{
    public static IResult Handle(HttpContext context)
    {
        var username = context.Request.Query["username"].ToString();

        if (string.IsNullOrEmpty(username))
        {
            return Results.BadRequest("Missing 'username' query parameter");
        }

        // SAFE: Newlines and carriage returns stripped before logging
        var sanitized = username
            .Replace("\n", "")
            .Replace("\r", "")
            .Replace("\t", "");

        Console.WriteLine("Login attempt for: " + sanitized);

        return Results.Text("Login attempt logged");
    }
}
