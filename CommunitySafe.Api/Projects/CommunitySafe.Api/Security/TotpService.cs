using System.Security.Cryptography;
using OtpNet;
using QRCoder;

namespace CommunitySafe.Api.Security;

public interface ITotpService
{
    string GenerateSecret();
    string BuildOtpAuthUri(string email, string secret, string issuer = "CommunitySafe");
    string BuildQrCodePngBase64(string otpAuthUri);
    bool Validate(string secret, string code);
}

public class TotpService : ITotpService
{
    public string GenerateSecret()
    {
        var bytes = RandomNumberGenerator.GetBytes(20);
        return Base32Encoding.ToString(bytes).Replace("=", string.Empty);
    }

    public string BuildOtpAuthUri(string email, string secret, string issuer = "CommunitySafe")
    {
        return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}" +
               $"?secret={secret}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits=6&period=30";
    }

    public string BuildQrCodePngBase64(string otpAuthUri)
    {
        using var generator = new QRCodeGenerator();
        var data = generator.CreateQrCode(otpAuthUri, QRCodeGenerator.ECCLevel.Q);
        var pngQrCode = new PngByteQRCode(data);
        var bytes = pngQrCode.GetGraphic(20);
        return Convert.ToBase64String(bytes);
    }

    public bool Validate(string secret, string code)
    {
        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(code))
            return false;

        try
        {
            var totp = new Totp(Base32Encoding.ToBytes(secret));
            return totp.VerifyTotp(code, out _, new VerificationWindow(previous: 1, future: 1));
        }
        catch
        {
            return false;
        }
    }
}
