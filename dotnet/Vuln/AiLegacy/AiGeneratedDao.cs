using System.Data.SQLite;
using System.Text;
using SastEval.Util;

namespace SastEval.Vuln.AiLegacy;

/// <summary>
/// CWE-89: SQL Injection via AI-generated CRUD methods using string interpolation.
/// Simulates code an AI assistant might generate without security awareness.
/// </summary>
public static class AiGeneratedDao
{
    public static IResult HandleCreate(HttpContext context)
    {
        var name = context.Request.Query["name"].ToString();
        var email = context.Request.Query["email"].ToString();

        if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(email))
        {
            return Results.BadRequest("Missing 'name' or 'email' query parameter");
        }

        var conn = DbUtil.GetConnection();

        // VULNERABLE: String interpolation in SQL (AI-generated anti-pattern)
        var sql = $"INSERT INTO users (username, email, password, role) VALUES ('{name}', '{email}', 'default', 'user')";

        using var cmd = new SQLiteCommand(sql, conn);
        cmd.ExecuteNonQuery();

        return Results.Ok($"User {name} created");
    }

    public static IResult HandleRead(HttpContext context)
    {
        var email = context.Request.Query["email"].ToString();

        if (string.IsNullOrEmpty(email))
        {
            return Results.BadRequest("Missing 'email' query parameter");
        }

        var conn = DbUtil.GetConnection();

        // VULNERABLE: String interpolation in SQL
        var sql = $"SELECT * FROM users WHERE email = '{email}'";

        using var cmd = new SQLiteCommand(sql, conn);
        using var reader = cmd.ExecuteReader();

        var sb = new StringBuilder();
        while (reader.Read())
        {
            sb.AppendLine($"User: {reader["username"]}, Email: {reader["email"]}, Role: {reader["role"]}");
        }

        return sb.Length > 0 ? Results.Text(sb.ToString()) : Results.NotFound("No user found");
    }

    public static IResult HandleUpdate(HttpContext context)
    {
        var id = context.Request.Query["id"].ToString();
        var email = context.Request.Query["email"].ToString();

        if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(email))
        {
            return Results.BadRequest("Missing 'id' or 'email' query parameter");
        }

        var conn = DbUtil.GetConnection();

        // VULNERABLE: String interpolation in SQL
        var sql = $"UPDATE users SET email = '{email}' WHERE id = {id}";

        using var cmd = new SQLiteCommand(sql, conn);
        var rows = cmd.ExecuteNonQuery();

        return Results.Ok($"Updated {rows} row(s)");
    }

    public static IResult HandleDelete(HttpContext context)
    {
        var id = context.Request.Query["id"].ToString();

        if (string.IsNullOrEmpty(id))
        {
            return Results.BadRequest("Missing 'id' query parameter");
        }

        var conn = DbUtil.GetConnection();

        // VULNERABLE: String interpolation in SQL
        var sql = $"DELETE FROM users WHERE id = {id}";

        using var cmd = new SQLiteCommand(sql, conn);
        var rows = cmd.ExecuteNonQuery();

        return Results.Ok($"Deleted {rows} row(s)");
    }
}
