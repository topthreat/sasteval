namespace SastEval.Vuln.Easy;

/// <summary>
/// CWE-614: Sensitive Cookie Without 'Secure' Flag - Session cookie set without Secure or HttpOnly.
/// </summary>
public static class InsecureCookieDirect
{
    public static IResult Handle(HttpContext context)
    {
        var token = Guid.NewGuid().ToString();

        // VULNERABLE: Cookie set without Secure and HttpOnly flags
        context.Response.Cookies.Append("session", token, new CookieOptions
        {
            Secure = false,
            HttpOnly = false
        });

        return Results.Text($"Session cookie set: {token}");
    }
}
