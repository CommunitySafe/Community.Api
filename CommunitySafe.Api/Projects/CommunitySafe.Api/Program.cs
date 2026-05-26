using System.Text;
using CommunitySafe.Api.Configuration;
using CommunitySafe.Api.Persistence;
using CommunitySafe.Api.Security;
using CommunitySafe.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// === Configuration ===
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));
builder.Services.Configure<BCryptOptions>(builder.Configuration.GetSection("BCrypt"));
builder.Services.Configure<EncryptionOptions>(builder.Configuration.GetSection("Encryption"));
builder.Services.Configure<LockoutOptions>(builder.Configuration.GetSection("Lockout"));
builder.Services.Configure<LgpdOptions>(builder.Configuration.GetSection("Lgpd"));
builder.Services.Configure<SmtpOptions>(builder.Configuration.GetSection("Smtp"));
builder.Services.Configure<OtpOptions>(builder.Configuration.GetSection("Otp"));

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

builder.Services.AddDbContext<AppDbContext>(options =>
    options
        .UseNpgsql(connectionString)
        .UseSnakeCaseNamingConvention());

// === Security services ===
var bcryptWorkFactor = builder.Configuration.GetValue<int?>("BCrypt:WorkFactor") ?? 12;
builder.Services.AddSingleton<IPasswordHasher>(_ => new BCryptPasswordHasher(bcryptWorkFactor));
builder.Services.AddSingleton<IJwtTokenService, JwtTokenService>();
builder.Services.AddSingleton<ITotpService, TotpService>();
builder.Services.AddSingleton<IEncryptionService, AesEncryptionService>();

// === App services ===
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IEmailOtpService, EmailOtpService>();

// === Auth ===
var jwt = builder.Configuration.GetSection("Jwt").Get<JwtOptions>() ?? new JwtOptions();
if (string.IsNullOrEmpty(jwt.SecretKey))
    jwt.SecretKey = "DEV_ONLY_INSECURE_KEY_change_in_production_64chars__________";

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = jwt.Issuer,
            ValidAudience = jwt.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.SecretKey)),
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });

builder.Services.AddAuthorization();

// === API ===
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "CommunitySafe API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT no formato: Bearer {token}",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            Array.Empty<string>()
        }
    });
});

// === CORS ===
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin();
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}
else
{
    app.UseHttpsRedirection();
}

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
