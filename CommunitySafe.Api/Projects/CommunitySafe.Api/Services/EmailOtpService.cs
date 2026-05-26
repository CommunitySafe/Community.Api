using System.Security.Cryptography;
using System.Text;
using CommunitySafe.Api.Configuration;
using CommunitySafe.Api.Domain;
using CommunitySafe.Api.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CommunitySafe.Api.Services;

public class EmailOtpService : IEmailOtpService
{
    private readonly AppDbContext _db;
    private readonly OtpOptions _options;

    public EmailOtpService(AppDbContext db, IOptions<OtpOptions> options)
    {
        _db = db;
        _options = options.Value;
    }

    public async Task<string> GenerateAndStoreAsync(Guid userId, OtpPurpose purpose, string? ip, CancellationToken ct)
    {
        // Invalida códigos anteriores não utilizados para o mesmo propósito.
        var pending = await _db.EmailOtpCodes
            .Where(o => o.UserId == userId && o.Purpose == purpose && o.UsedAt == null)
            .ToListAsync(ct);
        var now = DateTime.UtcNow;
        foreach (var p in pending)
            p.UsedAt = now;

        var code = GenerateNumericCode(_options.CodeLength);
        var entity = new EmailOtpCode
        {
            UserId = userId,
            Purpose = purpose,
            CodeHash = HashCode(code),
            CreatedAt = now,
            ExpiresAt = now.AddMinutes(_options.ValidityMinutes),
            IpAddress = ip
        };
        _db.EmailOtpCodes.Add(entity);
        await _db.SaveChangesAsync(ct);

        return code;
    }

    public async Task<bool> ValidateAndConsumeAsync(Guid userId, OtpPurpose purpose, string code, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(code))
            return false;

        var now = DateTime.UtcNow;
        var entity = await _db.EmailOtpCodes
            .Where(o => o.UserId == userId
                        && o.Purpose == purpose
                        && o.UsedAt == null
                        && o.ExpiresAt > now)
            .OrderByDescending(o => o.CreatedAt)
            .FirstOrDefaultAsync(ct);

        if (entity is null)
            return false;

        if (entity.FailedAttempts >= _options.MaxAttempts)
        {
            entity.UsedAt = now;
            await _db.SaveChangesAsync(ct);
            return false;
        }

        var expected = entity.CodeHash;
        var actual = HashCode(code);
        if (!FixedTimeEquals(expected, actual))
        {
            entity.FailedAttempts++;
            if (entity.FailedAttempts >= _options.MaxAttempts)
                entity.UsedAt = now;
            await _db.SaveChangesAsync(ct);
            return false;
        }

        entity.UsedAt = now;
        await _db.SaveChangesAsync(ct);
        return true;
    }

    private static string GenerateNumericCode(int length)
    {
        Span<byte> bytes = stackalloc byte[4];
        var sb = new StringBuilder(length);
        for (int i = 0; i < length; i++)
        {
            RandomNumberGenerator.Fill(bytes);
            var digit = (uint)BitConverter.ToInt32(bytes) % 10;
            sb.Append(digit);
        }
        return sb.ToString();
    }

    private static string HashCode(string code)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(code));
        return Convert.ToBase64String(bytes);
    }

    private static bool FixedTimeEquals(string a, string b)
    {
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
