using System.Security.Claims;
using CommunitySafe.Api.Domain;
using CommunitySafe.Api.Dtos;
using CommunitySafe.Api.Persistence;
using CommunitySafe.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace CommunitySafe.Api.Controllers;

[ApiController]
[Authorize]
[Route("api/me")]
public class MeController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly IAuditService _audit;

    public MeController(AppDbContext db, IAuditService audit)
    {
        _db = db;
        _audit = audit;
    }

    [HttpGet]
    public async Task<IActionResult> Get(CancellationToken ct)
    {
        if (!TryGetUserId(out var userId)) return Unauthorized();

        var user = await _db.Users.AsNoTracking()
            .FirstOrDefaultAsync(u => u.Id == userId && u.DeletedAt == null, ct);
        if (user is null) return NotFound();

        return Ok(new MeResponse(
            user.Id,
            user.FullName,
            user.Email,
            user.Role.ToString(),
            user.TwoFactorEnabled,
            user.CreatedAt));
    }

    [HttpGet("data")]
    public async Task<IActionResult> Data(CancellationToken ct)
    {
        if (!TryGetUserId(out var userId)) return Unauthorized();

        var user = await _db.Users.AsNoTracking()
            .Include(u => u.Consents)
            .FirstOrDefaultAsync(u => u.Id == userId && u.DeletedAt == null, ct);
        if (user is null) return NotFound();

        await _audit.LogAsync(AuditEventType.DadosExportados, true, "Consulta /api/me/data", userId, null,
            HttpContext.Connection.RemoteIpAddress?.ToString(), Request.Headers.UserAgent.ToString(), ct);

        var payload = new
        {
            user.Id,
            user.FullName,
            user.Email,
            Role = user.Role.ToString(),
            user.CreatedAt,
            user.TwoFactorEnabled,
            Consents = user.Consents.Select(c => new
            {
                Purpose = c.Purpose.ToString(),
                c.PolicyVersion,
                c.Granted,
                c.Timestamp,
                c.RevokedAt
            })
        };
        return Ok(payload);
    }

    [HttpDelete("account")]
    public async Task<IActionResult> Delete(CancellationToken ct)
    {
        if (!TryGetUserId(out var userId)) return Unauthorized();

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Id == userId && u.DeletedAt == null, ct);
        if (user is null) return NotFound();

        user.DeletedAt = DateTime.UtcNow;
        user.IsActive = false;

        var tokens = await _db.RefreshTokens.Where(t => t.UserId == userId && t.RevokedAt == null).ToListAsync(ct);
        foreach (var t in tokens)
        {
            t.RevokedAt = DateTime.UtcNow;
            t.RevokedReason = "AccountDeleted";
        }

        await _db.SaveChangesAsync(ct);
        await _audit.LogAsync(AuditEventType.ContaExcluida, true, "Solicitação de exclusão (soft delete)", userId, null,
            HttpContext.Connection.RemoteIpAddress?.ToString(), Request.Headers.UserAgent.ToString(), ct);

        return NoContent();
    }

    private bool TryGetUserId(out Guid userId)
    {
        var sub = User.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value
                  ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        return Guid.TryParse(sub, out userId);
    }
}
