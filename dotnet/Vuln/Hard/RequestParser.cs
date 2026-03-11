namespace SastEval.Vuln.Hard;

public static class RequestParser
{
    public static UserInputDto Parse(HttpRequest request)
    {
        return new UserInputDto
        {
            Payload = request.Query["payload"].ToString(),
            UserId = request.Query["userId"].ToString(),
            Role = request.Query["role"].ToString()
        };
    }
}
