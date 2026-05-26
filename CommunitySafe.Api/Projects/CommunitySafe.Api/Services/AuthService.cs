using System.Security.Cryptography;
using CommunitySafe.Api.Configuration;
using CommunitySafe.Api.Domain;
using CommunitySafe.Api.Dtos;
using CommunitySafe.Api.Persistence;
using CommunitySafe.Api.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CommunitySafe.Api.Services;

public class AuthService : IAuthService
{
    private readonly AppDbContext _db;
    private readonly IPasswordHasher _hasher;
    private readonly IJwtTokenService _jwt;
    private readonly ITotpService _totp;
    private readonly IEncryptionService _encryption;
    private readonly IAuditService _audit;
    private readonly IEmailService _email;
    private readonly IEmailOtpService _otp;
    private readonly LockoutOptions _lockout;
    private readonly LgpdOptions _lgpd;
    private readonly JwtOptions _jwtOptions;
    private readonly OtpOptions _otpOptions;

    public AuthService(
        AppDbContext db,
        IPasswordHasher hasher,
        IJwtTokenService jwt,
        ITotpService totp,
        IEncryptionService encryption,
        IAuditService audit,
        IEmailService email,
        IEmailOtpService otp,
        IOptions<LockoutOptions> lockout,
        IOptions<LgpdOptions> lgpd,
        IOptions<JwtOptions> jwtOptions,
        IOptions<OtpOptions> otpOptions)
    {
        _db = db;
        _hasher = hasher;
        _jwt = jwt;
        _totp = totp;
        _encryption = encryption;
        _audit = audit;
        _email = email;
        _otp = otp;
        _lockout = lockout.Value;
        _lgpd = lgpd.Value;
        _jwtOptions = jwtOptions.Value;
        _otpOptions = otpOptions.Value;
    }

    public async Task<AuthOutcome<RegisterResponse>> RegisterAsync(RegisterRequest req, string? ip, string? ua, CancellationToken ct)
    {
        if (!req.ConsentAccepted)
            return AuthOutcome<RegisterResponse>.Fail("É necessário aceitar a política de privacidade (LGPD).");

        if (!IsStrongPassword(req.Password))
            return AuthOutcome<RegisterResponse>.Fail("Senha não atende à política de segurança (mín. 12, maiúscula, minúscula, dígito, símbolo).");

        var emailNorm = req.Email.Trim().ToLowerInvariant();
        var exists = await _db.Users.AnyAsync(u => u.Email == emailNorm, ct);
        if (exists)
        {
            await _audit.LogAsync(AuditEventType.RegistroFalha, false, "E-mail já cadastrado", null, null, ip, ua, ct);
            return AuthOutcome<RegisterResponse>.Fail("E-mail já cadastrado.", 409);
        }

        var user = new User
        {
            FullName = req.FullName.Trim(),
            Email = emailNorm,
            Role = UserRole.Morador,
            EmailConfirmed = false,
            TwoFactorEnabled = true,
            IsActive = true,
            Credentials = new UserCredentials
            {
                PasswordHash = _hasher.Hash(req.Password),
                PasswordChangedAt = DateTime.UtcNow
            }
        };

        _db.Users.Add(user);

        var consent = new ConsentRecord
        {
            UserId = user.Id,
            Purpose = ConsentPurpose.Cadastro,
            PolicyVersion = _lgpd.PolicyVersion,
            Granted = true,
            Timestamp = DateTime.UtcNow,
            IpAddress = ip,
            UserAgent = ua
        };
        _db.ConsentRecords.Add(consent);

        await _db.SaveChangesAsync(ct);
        await _audit.LogAsync(AuditEventType.RegistroSucesso, true, "Novo cadastro", user.Id, null, ip, ua, ct);

        // E-mail de boas-vindas (não bloqueia o cadastro em caso de falha SMTP).
        try
        {
            await _email.SendWelcomeAsync(user.Email, user.FullName, ct);
        }
        catch (Exception ex)
        {
            await _audit.LogAsync(AuditEventType.RegistroSucesso, true,
                $"Falha ao enviar e-mail de boas-vindas: {ex.Message}", user.Id, null, ip, ua, ct);
        }

        return AuthOutcome<RegisterResponse>.Ok(new RegisterResponse(user.Id, user.Email));
    }

    public async Task<AuthOutcome<LoginResponse>> LoginAsync(LoginRequest req, string? ip, string? ua, CancellationToken ct)
    {
        var emailNorm = req.Email.Trim().ToLowerInvariant();

        var user = await _db.Users
            .Include(u => u.Credentials)
            .FirstOrDefaultAsync(u => u.Email == emailNorm && u.DeletedAt == null, ct);

        if (user is null || user.Credentials is null || !user.IsActive)
        {
            await _audit.LogAsync(AuditEventType.LoginFalha, false, "Usuário inexistente ou inativo", null, null, ip, ua, ct);
            _ = _hasher.Verify(req.Password, "$2a$12$abcdefghijklmnopqrstuv");
            return AuthOutcome<LoginResponse>.Fail("Credenciais inválidas.", 401);
        }

        if (user.Credentials.LockoutEndsAt is { } lockoutEnd && lockoutEnd > DateTime.UtcNow)
        {
            await _audit.LogAsync(AuditEventType.ContaBloqueada, false, "Tentativa em conta bloqueada", user.Id, null, ip, ua, ct);
            return AuthOutcome<LoginResponse>.Fail("Conta temporariamente bloqueada. Tente novamente mais tarde.", 423);
        }

        if (!_hasher.Verify(req.Password, user.Credentials.PasswordHash))
        {
            user.Credentials.FailedLoginAttempts++;
            if (user.Credentials.FailedLoginAttempts >= _lockout.MaxFailedAttempts)
            {
                var minutes = Math.Min(
                    _lockout.InitialLockoutMinutes * (int)Math.Pow(2, user.Credentials.FailedLoginAttempts - _lockout.MaxFailedAttempts),
                    _lockout.MaxLockoutMinutes);
                user.Credentials.LockoutEndsAt = DateTime.UtcNow.AddMinutes(minutes);
            }
            await _db.SaveChangesAsync(ct);
            await _audit.LogAsync(AuditEventType.LoginFalha, false, "Senha incorreta", user.Id, null, ip, ua, ct);
            return AuthOutcome<LoginResponse>.Fail("Credenciais inválidas.", 401);
        }

        user.Credentials.FailedLoginAttempts = 0;
        user.Credentials.LockoutEndsAt = null;
        user.Credentials.LastLoginAt = DateTime.UtcNow;

        if (user.TwoFactorEnabled)
        {
            await _db.SaveChangesAsync(ct);

            var code = await _otp.GenerateAndStoreAsync(user.Id, OtpPurpose.TwoFactorLogin, ip, ct);
            await _email.SendTwoFactorCodeAsync(user.Email, code, _otpOptions.ValidityMinutes, ct);
            await _audit.LogAsync(AuditEventType.OtpEmailEnviado, true, "Código 2FA enviado por e-mail", user.Id, null, ip, ua, ct);

            var temp = _jwt.CreateTempTwoFactorToken(user);
            return AuthOutcome<LoginResponse>.Ok(new LoginResponse(true, temp, null, null, null));
        }

        var (access, expires) = _jwt.CreateAccessToken(user);
        var (refreshToken, refreshHash) = _jwt.CreateRefreshToken();
        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = refreshHash,
            FamilyId = Guid.NewGuid(),
            ExpiresAt = DateTime.UtcNow.AddDays(_jwtOptions.RefreshTokenDays),
            IpAddress = ip,
            UserAgent = ua
        });

        await _db.SaveChangesAsync(ct);
        await _audit.LogAsync(AuditEventType.LoginSucesso, true, "Login bem-sucedido", user.Id, null, ip, ua, ct);

        return AuthOutcome<LoginResponse>.Ok(new LoginResponse(false, null, access, refreshToken, expires));
    }

    public async Task<AuthOutcome<LoginResponse>> VerifyTwoFactorAsync(TwoFactorVerifyRequest req, string? ip, string? ua, CancellationToken ct)
    {
        var principal = _jwt.ValidateTempToken(req.TempToken);
        if (principal is null)
            return AuthOutcome<LoginResponse>.Fail("Sessão de 2FA inválida ou expirada.", 401);

        var sub = principal.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value;
        if (!Guid.TryParse(sub, out var userId))
            return AuthOutcome<LoginResponse>.Fail("Token inválido.", 401);

        var user = await _db.Users.Include(u => u.Credentials)
            .FirstOrDefaultAsync(u => u.Id == userId && u.DeletedAt == null, ct);

        if (user is null || user.Credentials is null)
            return AuthOutcome<LoginResponse>.Fail("Usuário não encontrado.", 404);

        var valid = await _otp.ValidateAndConsumeAsync(user.Id, OtpPurpose.TwoFactorLogin, req.Code, ct);
        if (!valid)
        {
            await _audit.LogAsync(AuditEventType.OtpEmailFalha, false, "Código 2FA inválido", user.Id, null, ip, ua, ct);
            return AuthOutcome<LoginResponse>.Fail("Código inválido ou expirado.", 401);
        }

        var (access, expires) = _jwt.CreateAccessToken(user);
        var (refreshToken, refreshHash) = _jwt.CreateRefreshToken();
        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = refreshHash,
            FamilyId = Guid.NewGuid(),
            ExpiresAt = DateTime.UtcNow.AddDays(_jwtOptions.RefreshTokenDays),
            IpAddress = ip,
            UserAgent = ua
        });
        await _db.SaveChangesAsync(ct);
        await _audit.LogAsync(AuditEventType.OtpEmailVerificado, true, "2FA por e-mail verificado", user.Id, null, ip, ua, ct);

        return AuthOutcome<LoginResponse>.Ok(new LoginResponse(false, null, access, refreshToken, expires));
    }

    public async Task<AuthOutcome<LoginResponse>> RefreshAsync(RefreshRequest req, string? ip, string? ua, CancellationToken ct)
    {
        var hash = _jwt.HashRefreshToken(req.RefreshToken);
        var existing = await _db.RefreshTokens.Include(t => t.User)
            .FirstOrDefaultAsync(t => t.TokenHash == hash, ct);

        if (existing is null)
            return AuthOutcome<LoginResponse>.Fail("Refresh token inválido.", 401);

        if (existing.RevokedAt is not null)
        {
            var family = await _db.RefreshTokens.Where(t => t.FamilyId == existing.FamilyId && t.RevokedAt == null).ToListAsync(ct);
            foreach (var t in family)
            {
                t.RevokedAt = DateTime.UtcNow;
                t.RevokedReason = "Reuse detected";
            }
            await _db.SaveChangesAsync(ct);
            await _audit.LogAsync(AuditEventType.RefreshTokenReuso, false, "Reuso de refresh token detectado", existing.UserId, null, ip, ua, ct);
            return AuthOutcome<LoginResponse>.Fail("Refresh token inválido.", 401);
        }

        if (existing.ExpiresAt < DateTime.UtcNow || existing.User is null || existing.User.DeletedAt is not null)
            return AuthOutcome<LoginResponse>.Fail("Refresh token expirado.", 401);

        var (access, expires) = _jwt.CreateAccessToken(existing.User);
        var (newToken, newHash) = _jwt.CreateRefreshToken();

        existing.RevokedAt = DateTime.UtcNow;
        existing.RevokedReason = "Rotated";
        existing.ReplacedByTokenHash = newHash;

        _db.RefreshTokens.Add(new RefreshToken
        {
            UserId = existing.UserId,
            TokenHash = newHash,
            FamilyId = existing.FamilyId,
            ExpiresAt = DateTime.UtcNow.AddDays(_jwtOptions.RefreshTokenDays),
            IpAddress = ip,
            UserAgent = ua
        });

        await _db.SaveChangesAsync(ct);
        await _audit.LogAsync(AuditEventType.RefreshTokenRotacionado, true, "Refresh token rotacionado", existing.UserId, null, ip, ua, ct);

        return AuthOutcome<LoginResponse>.Ok(new LoginResponse(false, null, access, newToken, expires));
    }

    public async Task LogoutAsync(Guid userId, CancellationToken ct)
    {
        var tokens = await _db.RefreshTokens.Where(t => t.UserId == userId && t.RevokedAt == null).ToListAsync(ct);
        foreach (var t in tokens)
        {
            t.RevokedAt = DateTime.UtcNow;
            t.RevokedReason = "Logout";
        }
        await _db.SaveChangesAsync(ct);
        await _audit.LogAsync(AuditEventType.LogoutSucesso, true, "Logout", userId, null, null, null, ct);
    }

    public async Task RequestPasswordResetAsync(PasswordResetRequest req, string? ip, CancellationToken ct)
    {
        var emailNorm = req.Email.Trim().ToLowerInvariant();
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == emailNorm && u.DeletedAt == null, ct);

        await _audit.LogAsync(AuditEventType.RecuperacaoSenhaSolicitada, true, "Solicitação de recuperação de senha",
            user?.Id, $"email={emailNorm}", ip, null, ct);

        if (user is null) return;

        var code = await _otp.GenerateAndStoreAsync(user.Id, OtpPurpose.PasswordReset, ip, ct);
        await _email.SendPasswordResetCodeAsync(user.Email, code, _otpOptions.ValidityMinutes, ct);
    }

    public async Task<AuthOutcome<PasswordResetVerifyResponse>> VerifyPasswordResetCodeAsync(PasswordResetVerifyRequest req, string? ip, CancellationToken ct)
    {
        var emailNorm = req.Email.Trim().ToLowerInvariant();
        var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == emailNorm && u.DeletedAt == null, ct);

        if (user is null)
            return AuthOutcome<PasswordResetVerifyResponse>.Fail("Código inválido ou expirado.", 400);

        var valid = await _otp.ValidateAndConsumeAsync(user.Id, OtpPurpose.PasswordReset, req.Code, ct);
        if (!valid)
        {
            await _audit.LogAsync(AuditEventType.OtpEmailFalha, false, "Código de reset inválido", user.Id, null, ip, null, ct);
            return AuthOutcome<PasswordResetVerifyResponse>.Fail("Código inválido ou expirado.", 400);
        }

        var resetToken = _jwt.CreatePasswordResetToken(user);
        await _audit.LogAsync(AuditEventType.OtpEmailVerificado, true, "Código de reset verificado", user.Id, null, ip, null, ct);
        return AuthOutcome<PasswordResetVerifyResponse>.Ok(new PasswordResetVerifyResponse(resetToken));
    }

    public async Task<AuthOutcome<bool>> ConfirmPasswordResetAsync(ConfirmPasswordResetRequest req, string? ip, CancellationToken ct)
    {
        if (!IsStrongPassword(req.NewPassword))
            return AuthOutcome<bool>.Fail("Senha não atende à política de segurança.");

        var principal = _jwt.ValidatePasswordResetToken(req.Token);
        if (principal is null)
            return AuthOutcome<bool>.Fail("Token de redefinição inválido ou expirado.", 400);

        var sub = principal.FindFirst(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value;
        if (!Guid.TryParse(sub, out var userId))
            return AuthOutcome<bool>.Fail("Token inválido.", 400);

        var user = await _db.Users.Include(u => u.Credentials)
            .FirstOrDefaultAsync(u => u.Id == userId && u.DeletedAt == null, ct);

        if (user is null || user.Credentials is null)
            return AuthOutcome<bool>.Fail("Usuário não encontrado.", 404);

        user.Credentials.PasswordHash = _hasher.Hash(req.NewPassword);
        user.Credentials.PasswordChangedAt = DateTime.UtcNow;

        var tokens = await _db.RefreshTokens.Where(t => t.UserId == user.Id && t.RevokedAt == null).ToListAsync(ct);
        foreach (var t in tokens)
        {
            t.RevokedAt = DateTime.UtcNow;
            t.RevokedReason = "PasswordReset";
        }

        await _db.SaveChangesAsync(ct);
        await _audit.LogAsync(AuditEventType.SenhaRedefinida, true, "Senha redefinida via OTP por e-mail", user.Id, null, ip, null, ct);

        return AuthOutcome<bool>.Ok(true);
    }

    public async Task<AuthOutcome<TwoFactorSetupResponse>> SetupTwoFactorAsync(Guid userId, CancellationToken ct)
    {
        var user = await _db.Users.Include(u => u.Credentials)
            .FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || user.Credentials is null)
            return AuthOutcome<TwoFactorSetupResponse>.Fail("Usuário não encontrado.", 404);

        var secret = _totp.GenerateSecret();
        user.Credentials.TotpSecretEncrypted = _encryption.Encrypt(secret);
        await _db.SaveChangesAsync(ct);

        var uri = _totp.BuildOtpAuthUri(user.Email, secret);
        var qr = _totp.BuildQrCodePngBase64(uri);
        return AuthOutcome<TwoFactorSetupResponse>.Ok(new TwoFactorSetupResponse(secret, uri, qr));
    }

    public async Task<AuthOutcome<bool>> EnableTwoFactorAsync(Guid userId, TwoFactorEnableRequest req, CancellationToken ct)
    {
        var user = await _db.Users.Include(u => u.Credentials)
            .FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || user.Credentials is null || string.IsNullOrEmpty(user.Credentials.TotpSecretEncrypted))
            return AuthOutcome<bool>.Fail("Configure o 2FA primeiro.", 400);

        var secret = _encryption.Decrypt(user.Credentials.TotpSecretEncrypted);
        if (!_totp.Validate(secret, req.Code))
            return AuthOutcome<bool>.Fail("Código inválido.", 400);

        user.TwoFactorEnabled = true;
        await _db.SaveChangesAsync(ct);
        return AuthOutcome<bool>.Ok(true);
    }

    private static bool IsStrongPassword(string password)
    {
        if (string.IsNullOrEmpty(password) || password.Length < 12) return false;
        var hasUpper = password.Any(char.IsUpper);
        var hasLower = password.Any(char.IsLower);
        var hasDigit = password.Any(char.IsDigit);
        var hasSymbol = password.Any(c => !char.IsLetterOrDigit(c));
        return hasUpper && hasLower && hasDigit && hasSymbol;
    }
}
