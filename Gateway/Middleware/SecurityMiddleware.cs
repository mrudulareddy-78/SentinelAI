using System.Net;
using System.Text;

namespace Sentinel.Gateway.Middleware;

public sealed class SecurityMiddleware
{
    private readonly RequestDelegate _next;
    private static readonly string BlacklistPath = Path.GetFullPath(
        Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Shared", "logs", "blacklist.txt")
    );

    public SecurityMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, DatabaseService dbService)
    {
        // Blacklist check disabled for demo
        await _next(context).ConfigureAwait(false);
    }

    private static string NormalizeIdentifier(string? value)
    {
        var text = (value ?? string.Empty).Trim();
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        if (IPAddress.TryParse(text, out var ipAddress))
        {
            return ipAddress.ToString();
        }

        return text;
    }
}