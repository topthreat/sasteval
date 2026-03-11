namespace SastEval.Vuln.Medium;

/// <summary>
/// CWE-22: Path Traversal - User input used in file path without validation.
/// </summary>
public static class PathTraversalService
{
    private static string ResolvePath(string userInput)
    {
        // VULNERABLE: No validation or canonicalization of user input
        return Path.Combine("/data/uploads", userInput);
    }

    public static IResult Handle(HttpContext context)
    {
        var file = context.Request.Query["file"].ToString();

        if (string.IsNullOrEmpty(file))
        {
            return Results.BadRequest("Missing 'file' query parameter");
        }

        var path = ResolvePath(file);

        try
        {
            // VULNERABLE: Reading file at user-controlled path (e.g., ../../etc/passwd)
            var content = File.ReadAllBytes(path);
            return Results.File(content, "application/octet-stream", Path.GetFileName(path));
        }
        catch (FileNotFoundException)
        {
            return Results.NotFound($"File not found: {file}");
        }
        catch (Exception ex)
        {
            return Results.Problem($"Error reading file: {ex.Message}");
        }
    }
}
