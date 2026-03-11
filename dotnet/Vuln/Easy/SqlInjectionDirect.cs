using System.Data.SQLite;
using System.Text;
using SastEval.Util;

namespace SastEval.Vuln.Easy;

/// <summary>
/// CWE-89: SQL Injection - Direct string concatenation of user input into SQL query.
/// </summary>
public static class SqlInjectionDirect
{
    public static IResult Handle(HttpContext context)
    {
        var id = context.Request.Query["id"].ToString();

        if (string.IsNullOrEmpty(id))
        {
            return Results.BadRequest("Missing 'id' query parameter");
        }

        var conn = DbUtil.GetConnection();

        // VULNERABLE: Direct string concatenation with user input
        var sql = "SELECT * FROM users WHERE id = '" + id + "'";

        using var cmd = new SQLiteCommand(sql, conn);
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
