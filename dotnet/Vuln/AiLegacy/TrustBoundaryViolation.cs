using System.Data.SQLite;
using SastEval.Util;

namespace SastEval.Vuln.AiLegacy;

/// <summary>
/// CWE-501: Trust Boundary Violation - User input promoted into trusted session state
/// and immediately used to authorize an admin-only delete operation.
/// </summary>
public static class TrustBoundaryViolation
{
    public static IResult Handle(HttpContext context)
    {
        var role = context.Request.Query["role"].ToString();
        var userId = context.Request.Query["userId"].ToString();

        if (string.IsNullOrEmpty(role))
        {
            return Results.BadRequest("Missing 'role' query parameter");
        }

        // VULNERABLE: User-supplied role stored directly into trusted session
        context.Session.SetString("role", role);

        if (context.Session.GetString("role") == "admin")
        {
            var conn = DbUtil.GetConnection();
            using var cmd = new SQLiteCommand("DELETE FROM users WHERE id = @id", conn);
            cmd.Parameters.AddWithValue("@id", userId);
            var rows = cmd.ExecuteNonQuery();
            return Results.Ok(new { SessionRole = role, RowsAffected = rows });
        }

        return Results.Text($"Role set to: {role}");
    }
}
