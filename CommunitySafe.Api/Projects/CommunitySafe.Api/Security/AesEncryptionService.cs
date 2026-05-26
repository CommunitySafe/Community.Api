using System.Security.Cryptography;
using System.Text;
using CommunitySafe.Api.Configuration;
using Microsoft.Extensions.Options;

namespace CommunitySafe.Api.Security;

public interface IEncryptionService
{
    string Encrypt(string plaintext);
    string Decrypt(string ciphertext);
}

public class AesEncryptionService : IEncryptionService
{
    private readonly byte[] _key;

    public AesEncryptionService(IOptions<EncryptionOptions> options)
    {
        if (string.IsNullOrWhiteSpace(options.Value.MasterKeyBase64))
            throw new InvalidOperationException("Encryption.MasterKeyBase64 não configurado.");

        _key = Convert.FromBase64String(options.Value.MasterKeyBase64);
        if (_key.Length != 32)
            throw new InvalidOperationException("MasterKey deve ter 32 bytes (256 bits).");
    }

    public string Encrypt(string plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plain = Encoding.UTF8.GetBytes(plaintext);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];

        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(nonce, plain, cipher, tag);

        var result = new byte[nonce.Length + cipher.Length + tag.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
        Buffer.BlockCopy(cipher, 0, result, nonce.Length, cipher.Length);
        Buffer.BlockCopy(tag, 0, result, nonce.Length + cipher.Length, tag.Length);

        return Convert.ToBase64String(result);
    }

    public string Decrypt(string ciphertext)
    {
        var data = Convert.FromBase64String(ciphertext);
        var nonce = data.AsSpan(0, 12).ToArray();
        var tag = data.AsSpan(data.Length - 16, 16).ToArray();
        var cipher = data.AsSpan(12, data.Length - 12 - 16).ToArray();
        var plain = new byte[cipher.Length];

        using var aes = new AesGcm(_key, 16);
        aes.Decrypt(nonce, cipher, tag, plain);

        return Encoding.UTF8.GetString(plain);
    }
}
