using System.Data.SQLite;
using SastEval.Util;

namespace SastEval.Vuln.AiLegacy;

/// <summary>
/// CWE-306: Missing Authentication - Admin-only delete driven by a user-supplied query parameter.
/// </summary>
public static class AuthBypass
{
    public static IResult Handle(HttpContext context)
    {
        var userId = context.Request.Query["userId"].ToString();
        var isAdmin = context.Request.Query["isAdmin"].ToString();
        var authenticated = context.Session.GetString("authenticated") ?? "false";
        context.Session.SetString("authenticated", authenticated);

        if (isAdmin == "true")
        {
            var conn = DbUtil.GetConnection();
            using var cmd = new SQLiteCommand("DELETE FROM users WHERE id = @id", conn);
            cmd.Parameters.AddWithValue("@id", userId);
            var rows = cmd.ExecuteNonQuery();
            return Results.Ok(new { Authenticated = authenticated, RowsAffected = rows });
        }

        return Results.Ok(new { Message = "Access denied. Admins only." });
    }
}
