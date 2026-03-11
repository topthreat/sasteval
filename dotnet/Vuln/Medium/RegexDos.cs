using System.Text.RegularExpressions;

namespace SastEval.Vuln.Medium;

/// <summary>
/// CWE-1333: Inefficient Regular Expression Complexity - User-controlled regex pattern.
/// </summary>
public static class RegexDos
{
    public static IResult Handle(HttpContext context)
    {
        var pattern = context.Request.Query["pattern"].ToString();
        var input = context.Request.Query["input"].ToString();

        if (string.IsNullOrEmpty(pattern) || string.IsNullOrEmpty(input))
        {
            return Results.BadRequest("Missing 'pattern' or 'input' query parameter");
        }

        // VULNERABLE: User-controlled regex can cause ReDoS with catastrophic backtracking
        var regex = new Regex(pattern);
        var isMatch = regex.IsMatch(input);

        return Results.Text($"Match result: {isMatch}");
    }
}
