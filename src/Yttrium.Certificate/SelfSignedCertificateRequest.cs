using System.Security.Cryptography.X509Certificates;

namespace Yttrium.Certificate;

/// <summary />
public class SelfSignedCertificateRequest
{
    /// <summary />
    public DistinguishedName Name { get; set; } = default!;

    /// <summary />
    public int KeySize { get; set; } = 2048;

    /// <summary />
    public X509KeyUsageFlags KeyUsage { get; set; }

    /// <summary />
    public int ExpiresInDays { get; set; } = 1;
}


/// <summary />
public class DistinguishedName
{
    /// <summary />
    public string CommonName { get; set; } = default!;

    /// <summary />
    public string? EmailAddress { get; set; }

    /// <summary />
    public string? OrganizationalUnitName { get; set; }

    /// <summary />
    public string? StateOrProvinceName { get; set; }

    /// <summary />
    public string? Country { get; set; }

    /// <summary />
    public bool IsGovEntity { get; set; }
}
