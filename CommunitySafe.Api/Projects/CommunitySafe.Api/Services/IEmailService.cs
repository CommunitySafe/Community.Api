namespace CommunitySafe.Api.Services;

public interface IEmailService
{
    Task SendAsync(string to, string subject, string htmlBody, CancellationToken ct);
    Task SendWelcomeAsync(string to, string fullName, CancellationToken ct);
    Task SendTwoFactorCodeAsync(string to, string code, int validityMinutes, CancellationToken ct);
    Task SendPasswordResetCodeAsync(string to, string code, int validityMinutes, CancellationToken ct);
}
