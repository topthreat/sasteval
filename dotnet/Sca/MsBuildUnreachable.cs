using Microsoft.Build.Evaluation;

namespace SastEval.Sca;

/// <summary>
/// SCA validation note for CVE-2025-55247:
/// this sample proves package presence and user-controlled project loading, but it does
/// NOT faithfully exercise the advisory's documented DownloadFile/Linux temp-dir condition.
/// Treat it as a condition mismatch until replaced with an advisory-specific call path.
/// </summary>
public static class MsBuildUnreachable
{
    public static IResult Handle(HttpContext context)
    {
        var projectPath = context.Request.Query["projectPath"].ToString();

        if (string.IsNullOrEmpty(projectPath))
        {
            return Results.BadRequest("Missing 'projectPath' query parameter");
        }

        try
        {
            // Package/API usage only. This is not sufficient, by itself, to prove the
            // documented CVE-2025-55247 condition is reachable.
            var project = new Project(projectPath);
            var items = project.AllEvaluatedItems
                .Select(i => new { i.ItemType, i.EvaluatedInclude })
                .ToList();

            return Results.Ok(new { ProjectPath = projectPath, ItemCount = items.Count, Items = items });
        }
        catch (Exception ex)
        {
            return Results.Problem($"Error loading project: {ex.Message}");
        }
    }
}
