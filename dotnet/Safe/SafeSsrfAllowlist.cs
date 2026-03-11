namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-918: SSRF.
/// SAFE: Only HTTPS requests to allowlisted hosts are permitted.
/// </summary>
public static class SafeSsrfAllowlist
{
    private static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "status.example.com",
        "api.example.com"
    };

    public static async Task<IResult> Handle(HttpContext context)
    {
        var url = context.Request.Query["url"].ToString();

        if (string.IsNullOrEmpty(url))
        {
            return Results.BadRequest("Missing 'url' query parameter");
        }

        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !AllowedHosts.Contains(uri.Host))
        {
            return Results.BadRequest("URL not allowed");
        }

        // SAFE: Outbound request is restricted to an allowlisted host and scheme.
        using var client = new HttpClient();
        using var requestMessage = new HttpRequestMessage(HttpMethod.Head, uri);
        _ = await client.SendAsync(requestMessage);
        return Results.Json(new { AllowedHost = uri.Host });
    }
}
