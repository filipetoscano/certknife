using System.Security.Cryptography.X509Certificates;

namespace Yttrium.Certificate.Putty;

/// <summary />
public class PuttyKeyFile3Converter : ConverterBase
{
    /// <summary />
    public string Convert( X509Certificate2 certificate,
        string? certificatePassword,
        string? outputPassword,
        string? comment )
    {
        throw new NotImplementedException();
    }
}
