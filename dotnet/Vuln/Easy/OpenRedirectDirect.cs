namespace SastEval.Vuln.Easy;

/// <summary>
/// CWE-601: Open Redirect - User-supplied URL used directly in redirect without validation.
/// </summary>
public static class OpenRedirectDirect
{
    public static IResult Handle(HttpContext context)
    {
        var url = context.Request.Query["url"].ToString();

        if (string.IsNullOrEmpty(url))
        {
            return Results.BadRequest("Missing 'url' query parameter");
        }

        // VULNERABLE: Redirect to user-controlled URL without validation
        return Results.Redirect(url);
    }
}
