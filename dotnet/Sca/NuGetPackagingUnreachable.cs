using NuGet.Packaging;

namespace SastEval.Sca;

/// <summary>
/// SCA Reachability: CVE-2024-0057 / GHSA-68w7-72jg-6qpp
/// The NuGet.Packaging package is present, but NO methods from it are called,
/// making the advisory unreachable in this benchmark sample.
/// </summary>
public static class NuGetPackagingUnreachable
{
    // Reserved for future package verification feature
    // No NuGet.Packaging methods are called anywhere in this class.

    public static IResult Handle(HttpContext context)
    {
        return Results.Ok(new
        {
            Message = "Package verification feature is not yet implemented.",
            Status = "placeholder"
        });
    }
}
