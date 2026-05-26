using System.ComponentModel.DataAnnotations;

namespace CommunitySafe.Api.Dtos;

public record LoginRequest(
    [Required, EmailAddress] string Email,
    [Required] string Password);

public record RegisterRequest(
    [Required, MinLength(2)] string FullName,
    [Required, EmailAddress] string Email,
    [Required, MinLength(12)] string Password,
    bool ConsentAccepted);

public record TwoFactorVerifyRequest(
    [Required] string TempToken,
    [Required, MinLength(6), MaxLength(6)] string Code);

public record RefreshRequest([Required] string RefreshToken);

public record PasswordResetRequest([Required, EmailAddress] string Email);

public record PasswordResetVerifyRequest(
    [Required, EmailAddress] string Email,
    [Required, MinLength(6), MaxLength(6)] string Code);

public record PasswordResetVerifyResponse([Required] string ResetToken);

public record ConfirmPasswordResetRequest(
    [Required] string Token,
    [Required, MinLength(12)] string NewPassword);

public record ChangePasswordRequest(
    [Required] string CurrentPassword,
    [Required, MinLength(12)] string NewPassword);

public record TwoFactorEnableRequest(
    [Required, MinLength(6), MaxLength(6)] string Code);

public record LoginResponse(
    bool RequiresTwoFactor,
    string? TempToken,
    string? AccessToken,
    string? RefreshToken,
    DateTime? AccessTokenExpiresAt);

public record RegisterResponse(Guid Id, string Email);

public record TwoFactorSetupResponse(string SharedKey, string OtpAuthUri, string QrCodePngBase64);

public record MeResponse(
    Guid Id,
    string FullName,
    string Email,
    string Role,
    bool TwoFactorEnabled,
    DateTime CreatedAt);
