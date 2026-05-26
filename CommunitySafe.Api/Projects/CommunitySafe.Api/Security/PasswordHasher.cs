namespace CommunitySafe.Api.Security;

public interface IPasswordHasher
{
    string Hash(string password);
    bool Verify(string password, string hash);
}

public class BCryptPasswordHasher : IPasswordHasher
{
    private readonly int _workFactor;

    public BCryptPasswordHasher(int workFactor = 12)
    {
        _workFactor = workFactor;
    }

    public string Hash(string password) => BCrypt.Net.BCrypt.HashPassword(password, _workFactor);

    public bool Verify(string password, string hash)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }
        catch
        {
            return false;
        }
    }
}
