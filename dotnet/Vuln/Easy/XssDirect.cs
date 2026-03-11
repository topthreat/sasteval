namespace SastEval.Vuln.Easy;

/// <summary>
/// CWE-79: Cross-Site Scripting (Reflected) - User input rendered directly in HTML without encoding.
/// </summary>
public static class XssDirect
{
    public static IResult Handle(HttpContext context)
    {
        var name = context.Request.Query["name"].ToString();

        if (string.IsNullOrEmpty(name))
        {
            return Results.BadRequest("Missing 'name' query parameter");
        }

        // VULNERABLE: User input directly interpolated into HTML response
        return Results.Content($"<h1>Hello {name}</h1>", "text/html");
    }
}
