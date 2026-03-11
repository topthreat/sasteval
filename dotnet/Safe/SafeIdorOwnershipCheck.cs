using System.Data.SQLite;
using SastEval.Util;
using SastEval.Vuln.Hard;

namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-639: IDOR.
/// SAFE: Access is restricted to the session owner's object unless the trusted session role is admin.
/// </summary>
public static class SafeIdorOwnershipCheck
{
    public static IResult Handle(HttpContext context)
    {
        var dto = RequestParser.Parse(context.Request);
        var sessionUserId = context.Session.GetString("userId") ?? "2";
        var sessionRole = context.Session.GetString("role") ?? "user";
        context.Session.SetString("userId", sessionUserId);
        context.Session.SetString("role", sessionRole);

        if (string.IsNullOrEmpty(dto.UserId))
        {
            return Results.BadRequest("Missing 'userId' query parameter");
        }

        if (dto.UserId != sessionUserId && sessionRole != "admin")
        {
            return Results.Forbid();
        }

        using var conn = DbUtil.GetConnection();
        using var cmd = new SQLiteCommand(
            "SELECT id, username, email, role FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("@id", dto.UserId);
        using var reader = cmd.ExecuteReader();

        if (!reader.Read())
        {
            return Results.NotFound("No user found");
        }

        return Results.Json(new
        {
            SessionUserId = sessionUserId,
            SessionRole = sessionRole,
            RequestedUserId = dto.UserId,
            Id = reader["id"],
            Username = reader["username"],
            Email = reader["email"],
            Role = reader["role"]
        });
    }
}
