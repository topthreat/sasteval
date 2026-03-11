namespace SastEval.Vuln.AiLegacy;

/// <summary>
/// CWE-330: Use of Insufficiently Random Values - System.Random used for security token.
/// </summary>
public static class InsecureRandom
{
    public static IResult Handle(HttpContext context)
    {
        // VULNERABLE: System.Random is not cryptographically secure.
        // Tokens generated this way are predictable and can be brute-forced.
        var rng = new Random();
        var token = rng.Next().ToString();

        return Results.Ok(new
        {
            Token = token,
            Message = "Your password reset token has been generated."
        });
    }
}
