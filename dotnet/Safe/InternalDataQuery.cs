using System.Data.SQLite;
using System.Text;
using SastEval.Util;

namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-89: SQL built from internal hardcoded config values, NOT user input.
/// SAST tools should NOT flag this as SQL injection.
/// </summary>
public static class InternalDataQuery
{
    // Internal configuration - hardcoded values, not derived from user input
    private static readonly Dictionary<string, string> _config = new()
    {
        { "default_role", "user" },
        { "default_status", "active" },
        { "system_table", "users" }
    };

    public static IResult Handle(HttpContext context)
    {
        var conn = DbUtil.GetConnection();

        // SAFE: SQL is built from hardcoded internal config values, not user input.
        // String concatenation here is safe because the source is fully controlled.
        var table = _config["system_table"];
        var role = _config["default_role"];
        var sql = "SELECT * FROM " + table + " WHERE role = '" + role + "'";

        using var cmd = new SQLiteCommand(sql, conn);
        using var reader = cmd.ExecuteReader();

        var sb = new StringBuilder();
        while (reader.Read())
        {
            sb.AppendLine($"User: {reader["username"]}, Email: {reader["email"]}, Role: {reader["role"]}");
        }

        var result = sb.Length > 0 ? sb.ToString() : "No matching records";
        return Results.Text(result);
    }
}
