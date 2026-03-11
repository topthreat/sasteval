using System.Data.SQLite;
using SastEval.Util;

namespace SastEval.Vuln.Hard;

/// <summary>
/// Helper class for SqlInjectionCrossFile - executes raw SQL query.
/// </summary>
public static class QueryExecutor
{
    public static string Execute(string sql)
    {
        var conn = DbUtil.GetConnection();

        // VULNERABLE: Executes raw SQL string without parameterization
        using var cmd = new SQLiteCommand(sql, conn);
        using var reader = cmd.ExecuteReader();

        var result = "";
        while (reader.Read())
        {
            for (int i = 0; i < reader.FieldCount; i++)
            {
                result += $"{reader.GetName(i)}={reader[i]} ";
            }
            result += "\n";
        }

        return string.IsNullOrEmpty(result) ? "No results" : result;
    }
}
