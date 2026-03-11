using System.Data.SQLite;
using SastEval.Util;

namespace SastEval.Vuln.AiLegacy;

/// <summary>
/// CWE-754: Improper Check for Exceptional Conditions - Null handling fails open and
/// reaches an admin-only delete sink.
/// </summary>
public static class NullCheckBypass
{
    private static bool CanDeleteUser(string? token)
    {
        try
        {
            var length = token.Length;
            return length > 10 && token.StartsWith("admin-");
        }
        catch (NullReferenceException)
        {
            // VULNERABLE: Missing token unexpectedly grants access instead of denying it.
            return true;
        }
    }

    public static IResult Handle(HttpContext context)
    {
        var token = context.Request.Headers["X-Admin-Token"].ToString();
        var userId = context.Request.Query["userId"].ToString();

        if (!CanDeleteUser(string.IsNullOrEmpty(token) ? null : token))
        {
            return Results.Unauthorized();
        }

        var conn = DbUtil.GetConnection();
        using var cmd = new SQLiteCommand("DELETE FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("@id", userId);
        var rows = cmd.ExecuteNonQuery();
        return Results.Ok(new { RowsAffected = rows });
    }
}
