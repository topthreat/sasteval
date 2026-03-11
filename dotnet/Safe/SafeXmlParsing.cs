using System.Xml;

namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-611: XML parsing with DTD processing prohibited.
/// SAST tools should NOT flag this as XXE.
/// </summary>
public static class SafeXmlParsing
{
    public static async Task<IResult> Handle(HttpContext context)
    {
        using var reader = new StreamReader(context.Request.Body);
        var xml = await reader.ReadToEndAsync();

        if (string.IsNullOrEmpty(xml))
        {
            return Results.BadRequest("Empty request body");
        }

        // SAFE: DTD processing is explicitly prohibited, preventing XXE
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit
        };

        using var stringReader = new StringReader(xml);
        using var xmlReader = XmlReader.Create(stringReader, settings);

        try
        {
            var doc = new XmlDocument();
            doc.Load(xmlReader);
            return Results.Text(doc.OuterXml, "application/xml");
        }
        catch (XmlException ex)
        {
            return Results.BadRequest($"Invalid XML: {ex.Message}");
        }
    }
}
