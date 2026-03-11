using Ganss.Xss;

namespace SastEval.Util;

public static class SanitizerUtil
{
    private static readonly HtmlSanitizer _sanitizer;

    static SanitizerUtil()
    {
        _sanitizer = new HtmlSanitizer();
        // Strict config: only allow basic formatting tags
        _sanitizer.AllowedTags.Clear();
        _sanitizer.AllowedTags.Add("b");
        _sanitizer.AllowedTags.Add("i");
        _sanitizer.AllowedTags.Add("u");
        _sanitizer.AllowedTags.Add("em");
        _sanitizer.AllowedTags.Add("strong");
        _sanitizer.AllowedTags.Add("p");
        _sanitizer.AllowedTags.Add("br");
        _sanitizer.AllowedAttributes.Clear();
        _sanitizer.AllowedSchemes.Clear();
        _sanitizer.AllowedSchemes.Add("https");
    }

    public static string Sanitize(string html)
    {
        return _sanitizer.Sanitize(html);
    }
}
