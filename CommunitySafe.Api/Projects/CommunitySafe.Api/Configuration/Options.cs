namespace CommunitySafe.Api.Configuration;

public class JwtOptions
{
    public string Issuer { get; set; } = "CommunitySafe.API";
    public string Audience { get; set; } = "CommunitySafe.Clients";
    public string SecretKey { get; set; } = string.Empty;
    public int AccessTokenMinutes { get; set; } = 15;
    public int RefreshTokenDays { get; set; } = 7;
    public int TwoFactorTempTokenMinutes { get; set; } = 5;
}

public class BCryptOptions
{
    public int WorkFactor { get; set; } = 12;
}

public class EncryptionOptions
{
    public string MasterKeyBase64 { get; set; } = string.Empty;
}

public class LockoutOptions
{
    public int MaxFailedAttempts { get; set; } = 5;
    public int InitialLockoutMinutes { get; set; } = 15;
    public int MaxLockoutMinutes { get; set; } = 1440;
}

public class LgpdOptions
{
    public string PolicyVersion { get; set; } = "2026.02.v1";
    public int DataDeletionGracePeriodDays { get; set; } = 30;
}

public class SmtpOptions
{
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 587;
    public bool UseStartTls { get; set; } = true;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string FromAddress { get; set; } = "no-reply@communitysafe.app";
    public string FromName { get; set; } = "CommunitySafe";
    public bool LogToConsoleOnly { get; set; } = false;
}

public class OtpOptions
{
    public int CodeLength { get; set; } = 6;
    public int ValidityMinutes { get; set; } = 10;
    public int MaxAttempts { get; set; } = 5;
}
