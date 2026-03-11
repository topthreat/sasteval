using System.Data.SQLite;
using System.Text;
using SastEval.Util;

namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-89: Public handler uses parameterized queries.
/// Contains a private method with vulnerable SQL that is NEVER called (dead code).
/// SAST tools should ideally not flag this, or flag it with very low severity.
/// </summary>
public static class DeadCodeVuln
{
    public static IResult Handle(HttpContext context)
    {
        var id = context.Request.Query["id"].ToString();

        if (string.IsNullOrEmpty(id))
        {
            return Results.BadRequest("Missing 'id' query parameter");
        }

        var conn = DbUtil.GetConnection();

        // SAFE: Parameterized query in the actual handler
        using var cmd = new SQLiteCommand("SELECT * FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("@id", id);
        using var reader = cmd.ExecuteReader();

        var sb = new StringBuilder();
        while (reader.Read())
        {
            sb.AppendLine($"User: {reader["username"]}, Email: {reader["email"]}");
        }

        var result = sb.Length > 0 ? sb.ToString() : "No user found";
        return Results.Text(result);
    }

    // DEAD CODE: This method is never called from any code path.
    // It contains vulnerable SQL but is unreachable.
    private static string NeverCalled(string userInput)
    {
        var conn = DbUtil.GetConnection();
        var sql = "SELECT * FROM users WHERE username = '" + userInput + "'";
        using var cmd = new SQLiteCommand(sql, conn);
        using var reader = cmd.ExecuteReader();
        return reader.HasRows ? "found" : "not found";
    }
}
