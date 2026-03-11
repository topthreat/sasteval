using System.Data.SQLite;
using SastEval.Util;

namespace SastEval.Vuln.Easy;

/// <summary>
/// CWE-209: Information Exposure Through an Error Message - Full stack trace returned to client.
/// </summary>
public static class ErrorInfoLeakDirect
{
    public static IResult Handle(HttpContext context)
    {
        var id = context.Request.Query["id"].ToString();

        try
        {
            var conn = DbUtil.GetConnection();
            using var cmd = new SQLiteCommand("SELECT * FROM users WHERE id = " + id, conn);
            using var reader = cmd.ExecuteReader();
            return Results.Text("Query executed");
        }
        catch (Exception ex)
        {
            // VULNERABLE: Full exception details including stack trace returned to user
            return Results.Text(ex.ToString());
        }
    }
}
