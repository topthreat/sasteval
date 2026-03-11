using System.DirectoryServices;

namespace SastEval.Vuln.Medium;

/// <summary>
/// CWE-90: LDAP Injection - User input concatenated into LDAP search filter.
/// </summary>
public static class LdapInjection
{
    private static string SearchLdap(string username)
    {
        // VULNERABLE: User input directly concatenated into LDAP filter
        var filter = "(uid=" + username + ")";

        try
        {
            var entry = new DirectoryEntry("LDAP://localhost:389");
            var searcher = new DirectorySearcher(entry)
            {
                Filter = filter
            };

            var result = searcher.FindOne();
            return result?.GetDirectoryEntry().Name ?? "User not found";
        }
        catch (Exception ex)
        {
            return $"LDAP search error: {ex.Message}";
        }
    }

    public static IResult Handle(HttpContext context)
    {
        var username = context.Request.Query["username"].ToString();

        if (string.IsNullOrEmpty(username))
        {
            return Results.BadRequest("Missing 'username' query parameter");
        }

        var result = SearchLdap(username);
        return Results.Text(result);
    }
}
