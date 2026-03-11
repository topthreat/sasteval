#pragma warning disable SYSLIB0011 // BinaryFormatter is obsolete

using System.Runtime.Serialization.Formatters.Binary;

namespace SastEval.Vuln.Hard;

/// <summary>
/// CWE-502: Deserialization of Untrusted Data - BinaryFormatter with no type binder.
/// </summary>
public static class DeserializationHandler
{
    public static object? Deserialize(byte[] data)
    {
        if (data == null || data.Length == 0)
        {
            return null;
        }

        // VULNERABLE: BinaryFormatter with NO type binder allows arbitrary type instantiation
        var formatter = new BinaryFormatter();
        using var stream = new MemoryStream(data);
        return formatter.Deserialize(stream);
    }
}

#pragma warning restore SYSLIB0011
