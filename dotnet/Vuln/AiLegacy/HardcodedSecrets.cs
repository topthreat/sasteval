namespace SastEval.Vuln.AiLegacy;

/// <summary>
/// CWE-798: Use of Hard-coded Credentials - Secrets embedded directly in source code.
/// </summary>
public static class HardcodedSecrets
{
    // VULNERABLE: Hard-coded JWT signing key in source code
    private const string JwtSecret = "super-secret-jwt-key-12345";

    // VULNERABLE: Hard-coded API key in source code
    private const string ApiKey = "AKIA_EXAMPLE_KEY_DO_NOT_USE";

    public static IResult Handle(HttpContext context)
    {
        var action = context.Request.Query["action"].ToString();

        if (action == "verify")
        {
            return Results.Ok(new
            {
                Message = "Token verified using internal signing key.",
                KeyPrefix = JwtSecret[..5] + "..."
            });
        }

        if (action == "api-call")
        {
            return Results.Ok(new
            {
                Message = "External API called.",
                KeyUsed = ApiKey[..8] + "..."
            });
        }

        return Results.Ok(new { Message = "Specify action=verify or action=api-call" });
    }
}
