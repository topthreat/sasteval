using System.Xml;
using System.Xml.XPath;

namespace SastEval.Vuln.Medium;

/// <summary>
/// CWE-643: XPath Injection - User input concatenated into XPath expression.
/// </summary>
public static class XPathInjection
{
    private static readonly string UsersXml = @"
        <users>
            <user name='admin' password='s3cret' role='admin'/>
            <user name='bob' password='hunter2' role='user'/>
            <user name='charlie' password='qwerty' role='user'/>
        </users>";

    private static string QueryXml(string input)
    {
        // VULNERABLE: User input concatenated into XPath expression
        var xpath = "//users/user[@name='" + input + "']/password";

        var doc = new XmlDocument();
        doc.LoadXml(UsersXml);

        var nav = doc.CreateNavigator()!;
        var result = nav.SelectSingleNode(xpath);

        return result?.Value ?? "User not found";
    }

    public static IResult Handle(HttpContext context)
    {
        var username = context.Request.Query["username"].ToString();

        if (string.IsNullOrEmpty(username))
        {
            return Results.BadRequest("Missing 'username' query parameter");
        }

        var password = QueryXml(username);
        return Results.Text($"Password: {password}");
    }
}
