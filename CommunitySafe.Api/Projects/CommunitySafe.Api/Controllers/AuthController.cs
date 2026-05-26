using System.Security.Claims;
using CommunitySafe.Api.Dtos;
using CommunitySafe.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CommunitySafe.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _auth;

    public AuthController(IAuthService auth) => _auth = auth;

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest req, CancellationToken ct)
    {
        var result = await _auth.RegisterAsync(req, GetIp(), GetUa(), ct);
        if (!result.Success)
            return Problem(title: "Falha no cadastro", detail: result.Error, statusCode: result.StatusCode ?? 400);
        return Created($"/api/users/{result.Value!.Id}", result.Value);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest req, CancellationToken ct)
    {
        var result = await _auth.LoginAsync(req, GetIp(), GetUa(), ct);
        if (!result.Success)
            return Problem(title: "Falha no login", detail: result.Error, statusCode: result.StatusCode ?? 401);
        return Ok(result.Value);
    }

    [HttpPost("2fa/verify")]
    public async Task<IActionResult> VerifyTwoFactor([FromBody] TwoFactorVerifyRequest req, CancellationToken ct)
    {
        var result = await _auth.VerifyTwoFactorAsync(req, GetIp(), GetUa(), ct);
        if (!result.Success)
            return Problem(title: "Falha no 2FA", detail: result.Error, statusCode: result.StatusCode ?? 401);
        return Ok(result.Value);
    }

    [Authorize]
    [HttpPost("2fa/setup")]
    public async Task<IActionResult> SetupTwoFactor(CancellationToken ct)
    {
        if (!TryGetUserId(out var userId))
            return Unauthorized();
        var result = await _auth.SetupTwoFactorAsync(userId, ct);
        if (!result.Success)
            return Problem(title: "Falha", detail: result.Error, statusCode: result.StatusCode ?? 400);
        return Ok(result.Value);
    }

    [Authorize]
    [HttpPost("2fa/enable")]
    public async Task<IActionResult> EnableTwoFactor([FromBody] TwoFactorEnableRequest req, CancellationToken ct)
    {
        if (!TryGetUserId(out var userId))
            return Unauthorized();
        var result = await _auth.EnableTwoFactorAsync(userId, req, ct);
        if (!result.Success)
            return Problem(title: "Falha", detail: result.Error, statusCode: result.StatusCode ?? 400);
        return NoContent();
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest req, CancellationToken ct)
    {
        var result = await _auth.RefreshAsync(req, GetIp(), GetUa(), ct);
        if (!result.Success)
            return Problem(title: "Refresh inválido", detail: result.Error, statusCode: result.StatusCode ?? 401);
        return Ok(result.Value);
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        if (!TryGetUserId(out var userId))
            return Unauthorized();
        await _auth.LogoutAsync(userId, ct);
        return NoContent();
    }

    [HttpPost("password/forgot")]
    public async Task<IActionResult> Forgot([FromBody] PasswordResetRequest req, CancellationToken ct)
    {
        await _auth.RequestPasswordResetAsync(req, GetIp(), ct);
        return Ok(new { message = "Se o e-mail existir, um código foi enviado." });
    }

    [HttpPost("password/verify-code")]
    public async Task<IActionResult> VerifyResetCode([FromBody] PasswordResetVerifyRequest req, CancellationToken ct)
    {
        var result = await _auth.VerifyPasswordResetCodeAsync(req, GetIp(), ct);
        if (!result.Success)
            return Problem(title: "Falha", detail: result.Error, statusCode: result.StatusCode ?? 400);
        return Ok(result.Value);
    }

    [HttpPost("password/reset")]
    public async Task<IActionResult> Reset([FromBody] ConfirmPasswordResetRequest req, CancellationToken ct)
    {
        var result = await _auth.ConfirmPasswordResetAsync(req, GetIp(), ct);
        if (!result.Success)
            return Problem(title: "Falha", detail: result.Error, statusCode: result.StatusCode ?? 400);
        return NoContent();
    }

    private string? GetIp() => HttpContext.Connection.RemoteIpAddress?.ToString();
    private string? GetUa() => Request.Headers.UserAgent.ToString();
    private bool TryGetUserId(out Guid userId)
    {
        var sub = User.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value
                  ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(sub, out userId);
    }
}
