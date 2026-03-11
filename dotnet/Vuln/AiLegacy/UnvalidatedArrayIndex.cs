using System.Data.SQLite;
using SastEval.Util;

namespace SastEval.Vuln.AiLegacy;

/// <summary>
/// CWE-129: Improper Validation of Array Index - User-controlled index selects a
/// dangerous internal admin action.
/// </summary>
public static class UnvalidatedArrayIndex
{
    public static IResult Handle(HttpContext context)
    {
        var index = context.Request.Query["index"].ToString();

        if (string.IsNullOrEmpty(index))
        {
            return Results.BadRequest("Missing 'index' query parameter");
        }

        string[] adminActions =
        {
            "UPDATE users SET role = 'user' WHERE id = 2",
            "DELETE FROM users WHERE id = 1",
            "UPDATE users SET password = 'reset-required' WHERE id = 3"
        };

        // VULNERABLE: User-controlled index selects which privileged action to execute.
        var sql = adminActions[int.Parse(index)];
        var conn = DbUtil.GetConnection();
        using var cmd = new SQLiteCommand(sql, conn);
        var rows = cmd.ExecuteNonQuery();

        return Results.Ok(new { ActionIndex = index, RowsAffected = rows });
    }
}
