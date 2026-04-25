using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Sentinel.Gateway;

internal sealed class JwtTokenService
{
    private readonly byte[] _signingKey;
    private readonly string _issuer;
    private readonly string _audience;
    private readonly int _tokenLifetimeMinutes;

    public JwtTokenService(IConfiguration configuration)
    {
        _signingKey = Encoding.UTF8.GetBytes(configuration["Jwt:SigningKey"] ?? "SentinelJwtSigningKey-1234567890");
        _issuer = configuration["Jwt:Issuer"] ?? "Sentinel";
        _audience = configuration["Jwt:Audience"] ?? "SentinelClients";
        _tokenLifetimeMinutes = configuration.GetValue("Jwt:TokenLifetimeMinutes", 60);
    }

    public string CreateToken(string subject)
    {
        var now = DateTime.UtcNow;
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subject),
            new(JwtRegisteredClaimNames.UniqueName, subject),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
            new(ClaimTypes.Role, "GatewayUser")
        };

        var credentials = new SigningCredentials(new SymmetricSecurityKey(_signingKey), SecurityAlgorithms.HmacSha256);
        var token = new JwtSecurityToken(
            issuer: _issuer,
            audience: _audience,
            claims: claims,
            notBefore: now,
            expires: now.AddMinutes(_tokenLifetimeMinutes),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
