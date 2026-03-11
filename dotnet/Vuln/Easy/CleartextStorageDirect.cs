using System.Data.SQLite;
using SastEval.Util;

namespace SastEval.Vuln.Easy;

/// <summary>
/// CWE-312: Cleartext Storage of Sensitive Information - Credit card stored as plaintext in database.
/// </summary>
public static class CleartextStorageDirect
{
    public static IResult Handle(HttpContext context)
    {
        var creditCard = context.Request.Query["creditCard"].ToString();

        if (string.IsNullOrEmpty(creditCard))
        {
            return Results.BadRequest("Missing 'creditCard' query parameter");
        }

        var conn = DbUtil.GetConnection();

        // VULNERABLE: Sensitive credit card data stored in plaintext without encryption
        using var cmd = new SQLiteCommand(
            "INSERT INTO users (username, email, password, role) VALUES ('cardholder', @card, 'pass', 'user')",
            conn);
        cmd.Parameters.AddWithValue("@card", creditCard);
        cmd.ExecuteNonQuery();

        return Results.Text("Credit card stored successfully");
    }
}
