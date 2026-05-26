using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace CommunitySafe.Api.Domain;

public class User
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required, MaxLength(150)]
    public string FullName { get; set; } = string.Empty;

    [Required, MaxLength(254)]
    public string Email { get; set; } = string.Empty;

    public UserRole Role { get; set; } = UserRole.Morador;

    public bool EmailConfirmed { get; set; }

    public bool TwoFactorEnabled { get; set; }

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }
    public DateTime? DeletedAt { get; set; }

    public UserCredentials? Credentials { get; set; }
    public ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    public ICollection<ConsentRecord> Consents { get; set; } = new List<ConsentRecord>();
}

public class UserCredentials
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }
    public User? User { get; set; }

    [Required, MaxLength(100)]
    public string PasswordHash { get; set; } = string.Empty;

    public DateTime PasswordChangedAt { get; set; } = DateTime.UtcNow;

    public string? TotpSecretEncrypted { get; set; }

    public int FailedLoginAttempts { get; set; }
    public DateTime? LockoutEndsAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
}

public class RefreshToken
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }
    public User? User { get; set; }

    [Required, MaxLength(100)]
    public string TokenHash { get; set; } = string.Empty;

    public Guid FamilyId { get; set; }

    public DateTime IssuedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? RevokedReason { get; set; }
    public string? ReplacedByTokenHash { get; set; }

    [MaxLength(64)]
    public string? IpAddress { get; set; }

    [MaxLength(500)]
    public string? UserAgent { get; set; }

    [NotMapped]
    public bool IsActive => RevokedAt == null && DateTime.UtcNow < ExpiresAt;
}

public class PasswordResetToken
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }
    public User? User { get; set; }

    [Required, MaxLength(100)]
    public string TokenHash { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public DateTime? UsedAt { get; set; }

    [MaxLength(64)]
    public string? IpAddress { get; set; }
}

public class ConsentRecord
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }
    public User? User { get; set; }

    public ConsentPurpose Purpose { get; set; }

    [Required, MaxLength(20)]
    public string PolicyVersion { get; set; } = string.Empty;

    public bool Granted { get; set; }

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    [MaxLength(64)]
    public string? IpAddress { get; set; }

    [MaxLength(500)]
    public string? UserAgent { get; set; }

    public DateTime? RevokedAt { get; set; }
}

public class EmailOtpCode
{
    [Key]
    public Guid Id { get; set; } = Guid.NewGuid();

    public Guid UserId { get; set; }
    public User? User { get; set; }

    public OtpPurpose Purpose { get; set; }

    [Required, MaxLength(100)]
    public string CodeHash { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; set; }
    public DateTime? UsedAt { get; set; }

    public int FailedAttempts { get; set; }

    [MaxLength(64)]
    public string? IpAddress { get; set; }
}

public class AuditLog
{
    [Key]
    public long Id { get; set; }

    public Guid? UserId { get; set; }

    public AuditEventType EventType { get; set; }

    [Required, MaxLength(500)]
    public string Description { get; set; } = string.Empty;

    public string? Metadata { get; set; }

    [MaxLength(64)]
    public string? IpAddress { get; set; }

    [MaxLength(500)]
    public string? UserAgent { get; set; }

    public bool Success { get; set; }

    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}
