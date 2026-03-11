using System.Data.SQLite;
using System.Text;
using SastEval.Util;

namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-89: Uses parameterized queries for all user input.
/// SAST tools should NOT flag this as SQL injection.
/// </summary>
public static class SafeSqlQuery
{
    public static IResult Handle(HttpContext context)
    {
        var id = context.Request.Query["id"].ToString();

        if (string.IsNullOrEmpty(id))
        {
            return Results.BadRequest("Missing 'id' query parameter");
        }

        var conn = DbUtil.GetConnection();

        // SAFE: Parameterized query prevents SQL injection
        using var cmd = new SQLiteCommand("SELECT * FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("@id", id);
        using var reader = cmd.ExecuteReader();

        var sb = new StringBuilder();
        while (reader.Read())
        {
            sb.AppendLine($"User: {reader["username"]}, Email: {reader["email"]}, Role: {reader["role"]}");
        }

        var result = sb.Length > 0 ? sb.ToString() : "No user found";
        return Results.Text(result);
    }
}
