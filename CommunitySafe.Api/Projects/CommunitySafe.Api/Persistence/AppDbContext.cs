using CommunitySafe.Api.Domain;
using Microsoft.EntityFrameworkCore;

namespace CommunitySafe.Api.Persistence;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<User> Users => Set<User>();
    public DbSet<UserCredentials> UserCredentials => Set<UserCredentials>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<PasswordResetToken> PasswordResetTokens => Set<PasswordResetToken>();
    public DbSet<EmailOtpCode> EmailOtpCodes => Set<EmailOtpCode>();
    public DbSet<ConsentRecord> ConsentRecords => Set<ConsentRecord>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.HasDefaultSchema("User");

        modelBuilder.Entity<User>(b =>
        {
            b.HasIndex(u => u.Email).IsUnique();
            b.HasOne(u => u.Credentials)
                .WithOne(c => c.User!)
                .HasForeignKey<UserCredentials>(c => c.UserId);
        });

        modelBuilder.Entity<RefreshToken>(b =>
        {
            b.HasIndex(t => t.TokenHash).IsUnique();
            b.HasIndex(t => t.FamilyId);
            b.HasOne(t => t.User)
                .WithMany(u => u.RefreshTokens)
                .HasForeignKey(t => t.UserId);
        });

        modelBuilder.Entity<PasswordResetToken>(b =>
        {
            b.HasIndex(t => t.TokenHash).IsUnique();
        });

        modelBuilder.Entity<EmailOtpCode>(b =>
        {
            b.HasIndex(o => new { o.UserId, o.Purpose, o.UsedAt });
            b.HasIndex(o => o.ExpiresAt);
            b.HasOne(o => o.User)
                .WithMany()
                .HasForeignKey(o => o.UserId);
        });

        modelBuilder.Entity<ConsentRecord>(b =>
        {
            b.HasIndex(c => new { c.UserId, c.Purpose });
        });

        modelBuilder.Entity<AuditLog>(b =>
        {
            b.HasIndex(a => a.Timestamp);
            b.HasIndex(a => new { a.UserId, a.Timestamp });
        });
    }

    public override int SaveChanges()
    {
        EnforceAuditLogAppendOnly();
        return base.SaveChanges();
    }

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        EnforceAuditLogAppendOnly();
        return base.SaveChangesAsync(cancellationToken);
    }

    private void EnforceAuditLogAppendOnly()
    {
        var modified = ChangeTracker.Entries<AuditLog>()
            .Where(e => e.State == EntityState.Modified || e.State == EntityState.Deleted)
            .ToList();

        if (modified.Count > 0)
            throw new InvalidOperationException("AuditLog é append-only e não pode ser modificado ou excluído.");
    }
}
