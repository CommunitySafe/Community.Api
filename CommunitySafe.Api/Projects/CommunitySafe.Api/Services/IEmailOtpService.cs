using CommunitySafe.Api.Domain;

namespace CommunitySafe.Api.Services;

public interface IEmailOtpService
{
    Task<string> GenerateAndStoreAsync(Guid userId, OtpPurpose purpose, string? ip, CancellationToken ct);
    Task<bool> ValidateAndConsumeAsync(Guid userId, OtpPurpose purpose, string code, CancellationToken ct);
}
