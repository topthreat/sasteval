using Ganss.Xss;

namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-79: User input is sanitized via HtmlSanitizer before rendering.
/// SAST tools should NOT flag this as XSS.
/// </summary>
public static class FrameworkEscaped
{
    private static readonly HtmlSanitizer _sanitizer = new();

    public static IResult Handle(HttpContext context)
    {
        var userInput = context.Request.Query["input"].ToString();

        if (string.IsNullOrEmpty(userInput))
        {
            return Results.BadRequest("Missing 'input' query parameter");
        }

        // SAFE: HtmlSanitizer strips dangerous tags and attributes before rendering
        var sanitized = _sanitizer.Sanitize(userInput);

        return Results.Content(
            $"<html><body><h1>User Profile</h1><div>{sanitized}</div></body></html>",
            "text/html"
        );
    }
}
