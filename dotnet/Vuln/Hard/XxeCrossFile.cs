namespace SastEval.Vuln.Hard;

/// <summary>
/// CWE-611: XML External Entity (XXE) - Cross-file taint: Handler -> XmlProcessor.
/// </summary>
public static class XxeCrossFile
{
    public static async Task<IResult> Handle(HttpContext context)
    {
        if (context.Request.ContentLength == null || context.Request.ContentLength == 0)
        {
            return Results.BadRequest("Empty request body");
        }

        // VULNERABLE: Untrusted XML body passed to XmlProcessor which parses without disabling entities
        using var ms = new MemoryStream();
        await context.Request.Body.CopyToAsync(ms);
        ms.Position = 0;

        try
        {
            var result = XmlProcessor.Process(ms);
            return Results.Text(result, "application/xml");
        }
        catch (Exception ex)
        {
            return Results.Problem($"XML processing error: {ex.Message}");
        }
    }
}
