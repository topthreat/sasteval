namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-601: Redirect with whitelist validation.
/// SAST tools should NOT flag this as open redirect.
/// </summary>
public static class SafeRedirect
{
    private static readonly HashSet<string> AllowedPages = new()
    {
        "/home",
        "/profile",
        "/settings",
        "/dashboard",
        "/about"
    };

    public static IResult Handle(HttpContext context)
    {
        var page = context.Request.Query["page"].ToString();

        if (string.IsNullOrEmpty(page))
        {
            return Results.BadRequest("Missing 'page' query parameter");
        }

        // SAFE: Redirect only allowed to whitelisted paths
        if (AllowedPages.Contains(page))
        {
            return Results.Redirect(page);
        }

        return Results.BadRequest("Invalid redirect target");
    }
}
