using System.Data.SQLite;
using System.Text;
using SastEval.Util;

namespace SastEval.Vuln.Medium;

/// <summary>
/// CWE-89: SQL Injection - Multi-parameter cross-method string concatenation.
/// </summary>
public static class SqlInjectionMultiStep
{
    private static string BuildQuery(string table, string filter)
    {
        // VULNERABLE: Both table name and filter value concatenated into SQL
        return "SELECT * FROM " + table + " WHERE username = '" + filter + "'";
    }

    public static IResult Handle(HttpContext context)
    {
        var table = context.Request.Query["table"].ToString();
        var filter = context.Request.Query["filter"].ToString();

        if (string.IsNullOrEmpty(table) || string.IsNullOrEmpty(filter))
        {
            return Results.BadRequest("Missing 'table' or 'filter' query parameter");
        }

        var sql = BuildQuery(table, filter);
        var conn = DbUtil.GetConnection();

        using var cmd = new SQLiteCommand(sql, conn);
        using var reader = cmd.ExecuteReader();

        var sb = new StringBuilder();
        while (reader.Read())
        {
            for (int i = 0; i < reader.FieldCount; i++)
            {
                sb.Append($"{reader.GetName(i)}={reader[i]} ");
            }
            sb.AppendLine();
        }

        var result = sb.Length > 0 ? sb.ToString() : "No results found";
        return Results.Text(result);
    }
}
