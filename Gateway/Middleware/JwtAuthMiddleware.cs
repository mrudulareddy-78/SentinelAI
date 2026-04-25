using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Gateway.Middleware;

public sealed class JwtAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly TokenValidationParameters _validationParameters;

    public JwtAuthMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next;
        var issuer = configuration["Jwt:Issuer"] ?? "Sentinel";
        var audience = configuration["Jwt:Audience"] ?? "SentinelClients";
        var signingKey = Encoding.UTF8.GetBytes(configuration["Jwt:SigningKey"] ?? "SentinelJwtSigningKey-1234567890");

        _validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(signingKey),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            RequireExpirationTime = true,
            RequireSignedTokens = true
        };
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (IsBypassedPath(context.Request.Path))
        {
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (!context.Request.Headers.TryGetValue("Authorization", out var authHeaderValues))
        {
            await RejectAsync(context, "missing_authorization_header").ConfigureAwait(false);
            return;
        }

        var authHeader = authHeaderValues.ToString();
        if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            await RejectAsync(context, "invalid_authorization_scheme").ConfigureAwait(false);
            return;
        }

        var token = authHeader[7..].Trim();
        if (string.IsNullOrWhiteSpace(token))
        {
            await RejectAsync(context, "empty_bearer_token").ConfigureAwait(false);
            return;
        }

        try
        {
            var handler = new JwtSecurityTokenHandler();
            var principal = handler.ValidateToken(token, _validationParameters, out _);
            context.User = principal;
            await _next(context).ConfigureAwait(false);
        }
        catch (Exception)
        {
            await RejectAsync(context, "invalid_or_expired_token").ConfigureAwait(false);
        }
    }

    private static bool IsBypassedPath(PathString path)
    {
        return path.Equals("/token", StringComparison.OrdinalIgnoreCase)
            || path.Equals("/health", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task RejectAsync(HttpContext context, string reason)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.ContentType = "application/json";
        context.Response.Headers["WWW-Authenticate"] = "Bearer";
        await context.Response.WriteAsync($"{{\"error\":\"{reason}\"}}").ConfigureAwait(false);
    }
}
