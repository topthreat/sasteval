namespace SastEval.Vuln.Hard;

/// <summary>
/// CWE-502: Deserialization of Untrusted Data - Endpoint that passes raw request body to BinaryFormatter.
/// </summary>
public static class DeserializationEndpoint
{
    public static async Task<IResult> Handle(HttpContext context)
    {
        try
        {
            // Read raw request body
            using var ms = new MemoryStream();
            await context.Request.Body.CopyToAsync(ms);
            var bytes = ms.ToArray();

            if (bytes.Length == 0)
            {
                return Results.BadRequest("Empty request body");
            }

            // VULNERABLE: Untrusted bytes passed directly to BinaryFormatter.Deserialize
            var result = DeserializationHandler.Deserialize(bytes);
            return Results.Ok(new { Type = result?.GetType().FullName, Value = result?.ToString() });
        }
        catch (Exception ex)
        {
            return Results.Problem($"Deserialization error: {ex.Message}");
        }
    }
}
