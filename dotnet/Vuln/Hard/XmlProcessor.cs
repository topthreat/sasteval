using System.Xml;

namespace SastEval.Vuln.Hard;

/// <summary>
/// Helper class for XxeCrossFile - parses XML with insecure settings.
/// </summary>
public static class XmlProcessor
{
    public static string Process(Stream input)
    {
        // VULNERABLE: DTD processing enabled with XmlUrlResolver allows XXE
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = new XmlUrlResolver()
        };

        using var xmlReader = XmlReader.Create(input, settings);
        var doc = new XmlDocument();
        doc.Load(xmlReader);

        return doc.OuterXml;
    }
}
