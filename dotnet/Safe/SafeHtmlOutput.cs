using SastEval.Util;

namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-79: User input is sanitized via HtmlSanitizer before rendering.
/// SAST tools should NOT flag this as XSS.
/// </summary>
public static class SafeHtmlOutput
{
    public static IResult Handle(HttpContext context)
    {
        var userInput = context.Request.Query["content"].ToString();

        if (string.IsNullOrEmpty(userInput))
        {
            return Results.BadRequest("Missing 'content' query parameter");
        }

        // SAFE: Input is sanitized through a strict HtmlSanitizer before rendering
        var sanitized = SanitizerUtil.Sanitize(userInput);

        return Results.Content($"<html><body><div>{sanitized}</div></body></html>", "text/html");
    }
}
