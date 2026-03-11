using System.Xml;

namespace SastEval.Vuln.Easy;

/// <summary>
/// CWE-611: XML External Entity (XXE) - XML parsed with DTD processing enabled and XmlUrlResolver.
/// </summary>
public static class XxeDirect
{
    public static async Task<IResult> Handle(HttpContext context)
    {
        using var reader = new StreamReader(context.Request.Body);
        var xml = await reader.ReadToEndAsync();

        if (string.IsNullOrEmpty(xml))
        {
            return Results.BadRequest("Empty request body");
        }

        // VULNERABLE: DTD processing enabled with XmlUrlResolver allows XXE attacks
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = new XmlUrlResolver()
        };

        using var stringReader = new StringReader(xml);
        using var xmlReader = XmlReader.Create(stringReader, settings);

        var doc = new XmlDocument();
        doc.Load(xmlReader);

        return Results.Text(doc.OuterXml, "application/xml");
    }
}
