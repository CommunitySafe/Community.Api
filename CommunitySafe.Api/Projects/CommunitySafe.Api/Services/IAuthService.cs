using CommunitySafe.Api.Dtos;

namespace CommunitySafe.Api.Services;

public interface IAuthService
{
    Task<AuthOutcome<RegisterResponse>> RegisterAsync(RegisterRequest req, string? ip, string? ua, CancellationToken ct);
    Task<AuthOutcome<LoginResponse>> LoginAsync(LoginRequest req, string? ip, string? ua, CancellationToken ct);
    Task<AuthOutcome<LoginResponse>> VerifyTwoFactorAsync(TwoFactorVerifyRequest req, string? ip, string? ua, CancellationToken ct);
    Task<AuthOutcome<LoginResponse>> RefreshAsync(RefreshRequest req, string? ip, string? ua, CancellationToken ct);
    Task LogoutAsync(Guid userId, CancellationToken ct);
    Task RequestPasswordResetAsync(PasswordResetRequest req, string? ip, CancellationToken ct);
    Task<AuthOutcome<PasswordResetVerifyResponse>> VerifyPasswordResetCodeAsync(PasswordResetVerifyRequest req, string? ip, CancellationToken ct);
    Task<AuthOutcome<bool>> ConfirmPasswordResetAsync(ConfirmPasswordResetRequest req, string? ip, CancellationToken ct);
    Task<AuthOutcome<TwoFactorSetupResponse>> SetupTwoFactorAsync(Guid userId, CancellationToken ct);
    Task<AuthOutcome<bool>> EnableTwoFactorAsync(Guid userId, TwoFactorEnableRequest req, CancellationToken ct);
}

public record AuthOutcome<T>(bool Success, T? Value, string? Error, int? StatusCode = null)
{
    public static AuthOutcome<T> Ok(T value) => new(true, value, null);
    public static AuthOutcome<T> Fail(string error, int status = 400) => new(false, default, error, status);
}
