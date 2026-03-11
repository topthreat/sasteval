using System.Data.SQLite;
using SastEval.Util;
using SastEval.Vuln.Hard;

namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-306: Missing Authentication.
/// SAFE: Authorization uses trusted server-side session state rather than client input.
/// </summary>
public static class SafeAuthzFromSession
{
    public static IResult Handle(HttpContext context)
    {
        var dto = RequestParser.Parse(context.Request);
        var sessionRole = context.Session.GetString("role") ?? "user";
        context.Session.SetString("role", sessionRole);

        if (sessionRole != "admin")
        {
            return Results.Forbid();
        }

        using var conn = DbUtil.GetConnection();
        using var cmd = new SQLiteCommand("DELETE FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("@id", dto.UserId);
        var rows = cmd.ExecuteNonQuery();

        return Results.Ok(new
        {
            SessionRole = sessionRole,
            RowsAffected = rows
        });
    }
}
