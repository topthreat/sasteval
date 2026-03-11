namespace SastEval.Vuln.AiLegacy;

/// <summary>
/// CWE-295: Improper Certificate Validation - TLS certificate validation disabled.
/// </summary>
public static class InsecureTlsConfig
{
    public static async Task<IResult> Handle(HttpContext context)
    {
        var url = context.Request.Query["url"].ToString();

        if (string.IsNullOrEmpty(url))
        {
            return Results.BadRequest("Missing 'url' query parameter");
        }

        // VULNERABLE: Certificate validation bypassed - accepts any certificate
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (msg, cert, chain, errors) => true
        };

        using var client = new HttpClient(handler);

        try
        {
            var response = await client.GetStringAsync(url);
            return Results.Text(response);
        }
        catch (Exception ex)
        {
            return Results.Problem($"Request failed: {ex.Message}");
        }
    }
}
