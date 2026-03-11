namespace SastEval.Vuln.Medium;

/// <summary>
/// CWE-79: Cross-Site Scripting (Reflected) - Referer header rendered as HTML without encoding.
/// </summary>
public static class XssViaHeader
{
    public static IResult Handle(HttpContext context)
    {
        var referer = context.Request.Headers["Referer"].ToString();

        if (string.IsNullOrEmpty(referer))
        {
            return Results.BadRequest("Missing 'Referer' header");
        }

        // VULNERABLE: HTTP header value rendered directly as HTML content without encoding
        return Results.Content(
            $"<html><body><p>You came from: {referer}</p></body></html>",
            "text/html");
    }
}
