using System.Text.RegularExpressions;

namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-1333: ReDoS.
/// SAFE: User chooses from an allowlist of pre-approved regexes.
/// </summary>
public static class SafeRegexAllowlist
{
    private static readonly Dictionary<string, Regex> AllowedPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        ["digits"] = new(@"^\d+$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)),
        ["alnum"] = new(@"^[A-Za-z0-9]+$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100)),
        ["email"] = new(@"^[^@]+@[^@]+\.[^@]+$", RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100))
    };

    public static IResult Handle(HttpContext context)
    {
        var profile = context.Request.Query["profile"].ToString();
        var input = context.Request.Query["input"].ToString();

        if (!AllowedPatterns.TryGetValue(profile, out var regex))
        {
            return Results.BadRequest("Unknown pattern profile");
        }

        // SAFE: The regex itself is selected from a fixed allowlist.
        var matches = regex.IsMatch(input);
        return Results.Json(new { Profile = profile, Matches = matches });
    }
}
