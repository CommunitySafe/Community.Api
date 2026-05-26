using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using CommunitySafe.Api.Configuration;
using CommunitySafe.Api.Domain;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace CommunitySafe.Api.Security;

public interface IJwtTokenService
{
    (string token, DateTime expiresUtc) CreateAccessToken(User user);
    string CreateTempTwoFactorToken(User user);
    string CreatePasswordResetToken(User user);
    (string token, string hash) CreateRefreshToken();
    string HashRefreshToken(string token);
    ClaimsPrincipal? ValidateAccessToken(string token);
    ClaimsPrincipal? ValidateTempToken(string token);
    ClaimsPrincipal? ValidatePasswordResetToken(string token);
}

public class JwtTokenService : IJwtTokenService
{
    private readonly JwtOptions _options;

    public JwtTokenService(IOptions<JwtOptions> options) => _options = options.Value;

    public (string token, DateTime expiresUtc) CreateAccessToken(User user)
    {
        var expires = DateTime.UtcNow.AddMinutes(_options.AccessTokenMinutes);
        var token = WriteToken(BuildAccessClaims(user), expires);
        return (token, expires);
    }

    public string CreateTempTwoFactorToken(User user)
    {
        var expires = DateTime.UtcNow.AddMinutes(_options.TwoFactorTempTokenMinutes);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new("scope", "2fa_pending")
        };
        return WriteToken(claims, expires);
    }

    public string CreatePasswordResetToken(User user)
    {
        var expires = DateTime.UtcNow.AddMinutes(_options.TwoFactorTempTokenMinutes);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new("scope", "password_reset")
        };
        return WriteToken(claims, expires);
    }

    public (string token, string hash) CreateRefreshToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(64);
        var token = Convert.ToBase64String(bytes)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
        return (token, HashRefreshToken(token));
    }

    public string HashRefreshToken(string token)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return Convert.ToHexString(bytes);
    }

    public ClaimsPrincipal? ValidateAccessToken(string token) => Validate(token, requireScope: null);

    public ClaimsPrincipal? ValidateTempToken(string token) => Validate(token, requireScope: "2fa_pending");

    public ClaimsPrincipal? ValidatePasswordResetToken(string token) => Validate(token, requireScope: "password_reset");

    private ClaimsPrincipal? Validate(string token, string? requireScope)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_options.SecretKey);
            var principal = handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidIssuer = _options.Issuer,
                ValidAudience = _options.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30)
            }, out _);

            if (requireScope is not null)
            {
                var scope = principal.FindFirst("scope")?.Value;
                if (scope != requireScope) return null;
            }
            return principal;
        }
        catch
        {
            return null;
        }
    }

    private IEnumerable<Claim> BuildAccessClaims(User user)
    {
        return new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(ClaimTypes.Name, user.FullName),
            new(ClaimTypes.Role, user.Role.ToString())
        };
    }

    private string WriteToken(IEnumerable<Claim> claims, DateTime expires)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_options.SecretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var jwt = new JwtSecurityToken(
            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: DateTime.UtcNow,
            expires: expires,
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }
}
