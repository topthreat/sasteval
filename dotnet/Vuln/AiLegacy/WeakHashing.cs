using System.Security.Cryptography;
using System.Text;

namespace SastEval.Vuln.AiLegacy;

/// <summary>
/// CWE-328: Use of Weak Hash - MD5 used for password hashing.
/// </summary>
public static class WeakHashing
{
    public static IResult Handle(HttpContext context)
    {
        var password = context.Request.Query["password"].ToString();

        if (string.IsNullOrEmpty(password))
        {
            return Results.BadRequest("Missing 'password' query parameter");
        }

        // VULNERABLE: MD5 is cryptographically broken and unsuitable for password hashing.
        // Should use bcrypt, scrypt, Argon2, or at minimum PBKDF2.
        using var md5 = MD5.Create();
        var inputBytes = Encoding.UTF8.GetBytes(password);
        var hashBytes = md5.ComputeHash(inputBytes);
        var hash = Convert.ToHexString(hashBytes).ToLowerInvariant();

        return Results.Ok(new
        {
            PasswordHash = hash,
            Algorithm = "MD5",
            Message = "Password hashed and stored."
        });
    }
}
