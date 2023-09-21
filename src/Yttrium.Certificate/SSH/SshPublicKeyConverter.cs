using System.Security.Cryptography.X509Certificates;

namespace Yttrium.Certificate.SSH;

/// <summary />
public class SshPublicKeyConverter
{
    /// <summary />
    public string Convert( X509Certificate2 certificate, string? comment )
    {
        return "SSH PUBLIC KEY LINE";
    }
}
