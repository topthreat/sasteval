namespace SastEval.Vuln.Medium;

/// <summary>
/// CWE-918: Server-Side Request Forgery - User-supplied URL fetched without validation.
/// </summary>
public static class SsrfService
{
    private static async Task<string> FetchUrl(string url)
    {
        // VULNERABLE: No URL validation, allowlist, or blocklist
        using var client = new HttpClient();
        return await client.GetStringAsync(url);
    }

    public static async Task<IResult> Handle(HttpContext context)
    {
        var url = context.Request.Query["url"].ToString();

        if (string.IsNullOrEmpty(url))
        {
            return Results.BadRequest("Missing 'url' query parameter");
        }

        try
        {
            // VULNERABLE: User-controlled URL passed directly to HTTP client
            var content = await FetchUrl(url);
            return Results.Text(content);
        }
        catch (Exception ex)
        {
            return Results.Problem($"Error fetching URL: {ex.Message}");
        }
    }
}
