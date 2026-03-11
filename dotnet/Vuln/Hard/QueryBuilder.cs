namespace SastEval.Vuln.Hard;

/// <summary>
/// Helper class for SqlInjectionCrossFile - builds SQL query with string concatenation.
/// </summary>
public static class QueryBuilder
{
    public static string BuildUserQuery(string userId)
    {
        // VULNERABLE: User input concatenated into SQL query string
        return "SELECT * FROM users WHERE id = '" + userId + "'";
    }
}
