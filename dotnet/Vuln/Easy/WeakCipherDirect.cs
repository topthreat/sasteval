#pragma warning disable SYSLIB0021 // DES is obsolete

using System.Security.Cryptography;
using System.Text;

namespace SastEval.Vuln.Easy;

/// <summary>
/// CWE-327: Use of a Broken or Risky Cryptographic Algorithm - DES with hardcoded key.
/// </summary>
public static class WeakCipherDirect
{
    private static byte[] Encrypt(string data)
    {
        // VULNERABLE: DES is a weak cipher with only 56-bit key strength
        using var des = DES.Create();
        des.Key = Encoding.ASCII.GetBytes("12345678"); // Hardcoded 8-byte DES key
        des.IV = Encoding.ASCII.GetBytes("87654321");  // Hardcoded IV

        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write);
        var bytes = Encoding.UTF8.GetBytes(data);
        cs.Write(bytes, 0, bytes.Length);
        cs.FlushFinalBlock();
        return ms.ToArray();
    }

    public static IResult Handle(HttpContext context)
    {
        var data = context.Request.Query["data"].ToString();

        if (string.IsNullOrEmpty(data))
        {
            return Results.BadRequest("Missing 'data' query parameter");
        }

        var encrypted = Encrypt(data);
        return Results.Text(Convert.ToBase64String(encrypted));
    }
}

#pragma warning restore SYSLIB0021
