namespace SastEval.Vuln.AiLegacy;

/// <summary>
/// CWE-598: Use of GET Request Method With Sensitive Query Strings - Session token in URL.
/// </summary>
public static class CookieInUrl
{
    public static IResult Handle(HttpContext context)
    {
        var token = context.Request.Cookies["session"] ?? Guid.NewGuid().ToString();

        // VULNERABLE: Sensitive session token passed as query string parameter in redirect URL
        return Results.Redirect("/dashboard?token=" + token);
    }
}
