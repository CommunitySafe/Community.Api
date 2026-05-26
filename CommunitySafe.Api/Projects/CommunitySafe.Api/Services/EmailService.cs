using CommunitySafe.Api.Configuration;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace CommunitySafe.Api.Services;

public class EmailService : IEmailService
{
    private readonly SmtpOptions _smtp;
    private readonly ILogger<EmailService> _logger;

    public EmailService(IOptions<SmtpOptions> smtp, ILogger<EmailService> logger)
    {
        _smtp = smtp.Value;
        _logger = logger;
    }

    public async Task SendAsync(string to, string subject, string htmlBody, CancellationToken ct)
    {
        if (_smtp.LogToConsoleOnly || string.IsNullOrWhiteSpace(_smtp.Host))
        {
            _logger.LogInformation("[EMAIL-DEV] To={To} | Subject={Subject}\n{Body}", to, subject, htmlBody);
            return;
        }

        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(_smtp.FromName, _smtp.FromAddress));
        message.To.Add(MailboxAddress.Parse(to));
        message.Subject = subject;
        message.Body = new BodyBuilder { HtmlBody = htmlBody }.ToMessageBody();

        using var client = new SmtpClient();
        var socketOption = _smtp.UseStartTls
            ? SecureSocketOptions.StartTls
            : SecureSocketOptions.SslOnConnect;

        await client.ConnectAsync(_smtp.Host, _smtp.Port, socketOption, ct);
        if (!string.IsNullOrEmpty(_smtp.Username))
            await client.AuthenticateAsync(_smtp.Username, _smtp.Password, ct);

        await client.SendAsync(message, ct);
        await client.DisconnectAsync(true, ct);
    }

    public Task SendWelcomeAsync(string to, string fullName, CancellationToken ct)
    {
        var html = $$"""
            <div style="font-family: Arial, sans-serif; max-width: 540px; margin: 0 auto; color:#1b1c1a;">
              <h2 style="color:#005454;">Bem-vindo(a), {{fullName}}!</h2>
              <p>Sua conta no <strong>CommunitySafe</strong> foi criada com sucesso.</p>
              <p>O CommunitySafe é a plataforma que conecta moradores e síndicos para
              tornar nossa comunidade mais segura, com comunicação direta, registro
              de ocorrências e gestão transparente.</p>
              <p><strong>Próximos passos:</strong></p>
              <ul>
                <li>Faça login no aplicativo</li>
                <li>Complete seu perfil</li>
                <li>Ative a verificação em duas etapas para mais segurança</li>
              </ul>
              <p style="color:#3e4948; font-size:12px; margin-top:32px;">
                Se você não criou esta conta, ignore este e-mail.<br/>
                Seus dados são protegidos por criptografia AES-256 e tratados conforme a LGPD.
              </p>
            </div>
            """;
        return SendAsync(to, "Bem-vindo ao CommunitySafe", html, ct);
    }

    public Task SendTwoFactorCodeAsync(string to, string code, int validityMinutes, CancellationToken ct)
    {
        var html = $$"""
            <div style="font-family: Arial, sans-serif; max-width: 540px; margin: 0 auto; color:#1b1c1a;">
              <h2 style="color:#005454;">Seu código de verificação</h2>
              <p>Use o código abaixo para concluir seu login:</p>
              <div style="font-size:32px; font-weight:bold; letter-spacing:6px;
                          background:#f5f3f0; padding:16px; text-align:center;
                          border-radius:8px; margin:24px 0;">{{code}}</div>
              <p>O código expira em <strong>{{validityMinutes}} minutos</strong>.</p>
              <p style="color:#3e4948; font-size:12px; margin-top:32px;">
                Se você não tentou fazer login, ignore este e-mail e considere alterar sua senha.
              </p>
            </div>
            """;
        return SendAsync(to, "Código de verificação - CommunitySafe", html, ct);
    }

    public Task SendPasswordResetCodeAsync(string to, string code, int validityMinutes, CancellationToken ct)
    {
        var html = $$"""
            <div style="font-family: Arial, sans-serif; max-width: 540px; margin: 0 auto; color:#1b1c1a;">
              <h2 style="color:#005454;">Recuperação de senha</h2>
              <p>Recebemos uma solicitação para redefinir sua senha. Use o código abaixo no aplicativo:</p>
              <div style="font-size:32px; font-weight:bold; letter-spacing:6px;
                          background:#f5f3f0; padding:16px; text-align:center;
                          border-radius:8px; margin:24px 0;">{{code}}</div>
              <p>O código expira em <strong>{{validityMinutes}} minutos</strong>.</p>
              <p>Depois de digitar o código, você poderá criar uma nova senha.</p>
              <p style="color:#3e4948; font-size:12px; margin-top:32px;">
                Se você não solicitou esta recuperação, ignore este e-mail.
                Sua senha atual continua válida.
              </p>
            </div>
            """;
        return SendAsync(to, "Recuperação de senha - CommunitySafe", html, ct);
    }
}
