namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-22: Path Traversal.
/// SAFE: Canonicalized path must remain under the fixed uploads directory.
/// </summary>
public static class SafePathTraversal
{
    private static readonly string BaseDir = Path.GetFullPath("/data/uploads");

    public static IResult Handle(HttpContext context)
    {
        var file = context.Request.Query["file"].ToString();

        if (string.IsNullOrEmpty(file))
        {
            return Results.BadRequest("Missing 'file' query parameter");
        }

        var requested = Path.GetFullPath(Path.Combine(BaseDir, file));

        // SAFE: The canonicalized path must stay under the fixed base directory.
        if (!requested.StartsWith(BaseDir + Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            return Results.BadRequest("Invalid file path");
        }

        // SAFE: File read occurs only after canonical path enforcement.
        var content = File.ReadAllBytes(requested);
        return Results.File(content, "application/octet-stream", Path.GetFileName(requested));
    }
}
