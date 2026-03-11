using System.Security.Cryptography;
using System.Text;

namespace SastEval.Safe;

/// <summary>
/// True Negative for CWE-327: Strong AES encryption with random key and IV.
/// SAST tools should NOT flag this as weak cryptography.
/// </summary>
public static class SafeCrypto
{
    public static IResult Handle(HttpContext context)
    {
        var data = context.Request.Query["data"].ToString();

        if (string.IsNullOrEmpty(data))
        {
            return Results.BadRequest("Missing 'data' query parameter");
        }

        // SAFE: AES with randomly generated key and IV
        using var aes = Aes.Create();
        aes.GenerateKey();
        aes.GenerateIV();

        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write);
        var bytes = Encoding.UTF8.GetBytes(data);
        cs.Write(bytes, 0, bytes.Length);
        cs.FlushFinalBlock();

        var encrypted = Convert.ToBase64String(ms.ToArray());
        return Results.Text($"Encrypted: {encrypted}");
    }
}
