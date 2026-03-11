using System.Data.SQLite;
using System.Text;
using SastEval.Util;

namespace SastEval.Vuln.Hard;

/// <summary>
/// CWE-639: Insecure Direct Object Reference - Authorization based on client-supplied values.
/// </summary>
public static class IdorController
{
    public static IResult HandleGet(HttpContext context)
    {
        var dto = RequestParser.Parse(context.Request);
        var sessionUserId = context.Session.GetString("userId") ?? "2";
        context.Session.SetString("userId", sessionUserId);

        if (string.IsNullOrEmpty(dto.UserId))
        {
            return Results.BadRequest("Missing 'userId' query parameter");
        }

        var conn = DbUtil.GetConnection();

        // VULNERABLE (Horizontal IDOR): A real session user exists, but the handler
        // still returns another user's profile based only on the requested object ID.
        using var cmd = new SQLiteCommand(
            "SELECT id, username, email, password, role FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("@id", dto.UserId);
        using var reader = cmd.ExecuteReader();

        if (reader.Read())
        {
            return Results.Json(new
            {
                SessionUserId = sessionUserId,
                RequestedUserId = dto.UserId,
                Id = reader["id"],
                Username = reader["username"],
                Email = reader["email"],
                Password = reader["password"],
                Role = reader["role"]
            });
        }

        return Results.NotFound("No user found");
    }

    public static IResult HandlePost(HttpContext context)
    {
        var dto = RequestParser.Parse(context.Request);
        var sessionRole = context.Session.GetString("role") ?? "user";
        context.Session.SetString("role", sessionRole);

        // VULNERABLE (Vertical IDOR): Authorization check uses the client-supplied role
        // instead of the server-side session role.
        if (dto.Role != "admin")
        {
            return Results.Unauthorized();
        }

        // Perform admin operation
        var conn = DbUtil.GetConnection();

        if (!string.IsNullOrEmpty(dto.UserId))
        {
            using var cmd = new SQLiteCommand("DELETE FROM users WHERE id = @id", conn);
            cmd.Parameters.AddWithValue("@id", dto.UserId);
            var rows = cmd.ExecuteNonQuery();
            return Results.Ok(new
            {
                SessionRole = sessionRole,
                TrustedRole = dto.Role,
                RowsAffected = rows
            });
        }

        return Results.BadRequest("Missing 'userId' for admin operation");
    }
}
