namespace SastEval.Vuln.Hard;

/// <summary>
/// CWE-89: SQL Injection - Three-class taint chain: Handler -> QueryBuilder -> QueryExecutor.
/// </summary>
public static class SqlInjectionCrossFile
{
    public static IResult Handle(HttpContext context)
    {
        var userId = context.Request.Query["userId"].ToString();

        if (string.IsNullOrEmpty(userId))
        {
            return Results.BadRequest("Missing 'userId' query parameter");
        }

        // VULNERABLE: User input flows across three classes without sanitization
        var sql = QueryBuilder.BuildUserQuery(userId);
        var result = QueryExecutor.Execute(sql);

        return Results.Text(result);
    }
}
