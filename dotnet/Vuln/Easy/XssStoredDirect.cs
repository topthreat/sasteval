using System.Data.SQLite;
using System.Text;
using SastEval.Util;

namespace SastEval.Vuln.Easy;

/// <summary>
/// CWE-79: Cross-Site Scripting (Stored) - User comment stored in DB and rendered as HTML without encoding.
/// </summary>
public static class XssStoredDirect
{
    public static IResult HandlePost(HttpContext context)
    {
        var comment = context.Request.Query["comment"].ToString();

        if (string.IsNullOrEmpty(comment))
        {
            return Results.BadRequest("Missing 'comment' query parameter");
        }

        var conn = DbUtil.GetConnection();

        // VULNERABLE: Storing raw user input without sanitization
        using var cmd = new SQLiteCommand("INSERT INTO comments (body) VALUES (@body)", conn);
        cmd.Parameters.AddWithValue("@body", comment);
        cmd.ExecuteNonQuery();

        return Results.Ok("Comment stored");
    }

    public static IResult HandleGet(HttpContext context)
    {
        var conn = DbUtil.GetConnection();

        using var cmd = new SQLiteCommand("SELECT body FROM comments", conn);
        using var reader = cmd.ExecuteReader();

        var sb = new StringBuilder();
        sb.Append("<html><body><h1>Comments</h1>");

        while (reader.Read())
        {
            var body = reader["body"].ToString();
            // VULNERABLE: Rendering stored user input as raw HTML without encoding
            sb.Append($"<div class='comment'>{body}</div>");
        }

        sb.Append("</body></html>");

        return Results.Content(sb.ToString(), "text/html");
    }
}
