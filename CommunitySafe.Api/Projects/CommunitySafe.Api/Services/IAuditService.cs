using CommunitySafe.Api.Domain;
using CommunitySafe.Api.Persistence;

namespace CommunitySafe.Api.Services;

public interface IAuditService
{
    Task LogAsync(
        AuditEventType eventType,
        bool success,
        string description,
        Guid? userId = null,
        string? metadata = null,
        string? ipAddress = null,
        string? userAgent = null,
        CancellationToken cancellationToken = default);
}

public class AuditService : IAuditService
{
    private readonly AppDbContext _db;

    public AuditService(AppDbContext db) => _db = db;

    public async Task LogAsync(
        AuditEventType eventType,
        bool success,
        string description,
        Guid? userId = null,
        string? metadata = null,
        string? ipAddress = null,
        string? userAgent = null,
        CancellationToken cancellationToken = default)
    {
        var log = new AuditLog
        {
            EventType = eventType,
            Success = success,
            Description = description,
            UserId = userId,
            Metadata = metadata,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Timestamp = DateTime.UtcNow
        };

        _db.AuditLogs.Add(log);
        await _db.SaveChangesAsync(cancellationToken);
    }
}
