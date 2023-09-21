using McMaster.Extensions.CommandLineUtils;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace certknife;

/// <summary />
[Command( "create", Description = "Creates a new self-signed X509 certificate" )]
public class CreateCommand
{
    /// <summary />
    [Option( "--common-name", CommandOptionType.SingleValue, Description = "DN: Common name" )]
    public string CommonName { get; set; } = Environment.UserName;

    /// <summary />
    [Option( "--ou", CommandOptionType.SingleValue, Description = "DN: Organizational Unit Name" )]
    public string? OrganizationalUnitName { get; set; }

    /// <summary />
    [Option( "--country", CommandOptionType.SingleValue, Description = "DN: Country" )]
    public string? Country { get; set; }

    /// <summary />
    [Option( "--gov", CommandOptionType.NoValue, Description = "DN: If specified, indicates government entity" )]
    public bool IsGovEntity { get; set; }


    /// <summary />
    [Option( "--expires-in", CommandOptionType.SingleValue, Description = "Number of days, after which the certificate will expire." )]
    public int ExpiresInDays { get; set; } = 365;

    /// <summary />
    [Option( "--key-size", CommandOptionType.SingleValue, Description = "Key size: 2048 or 4096" )]
    public int KeySize { get; set; } = 2048;


    /// <summary />
    [Option( "-o|--output", CommandOptionType.SingleValue, Description = "Name of output PFX file." )]
    public string OutputFile { get; set; } = "out.pfx";

    /// <summary />
    [Option( "--password", CommandOptionType.SingleValue, Description = "Password protecting PFX file." )]
    public string? Password { get; set; }


    /// <summary />
    public int OnExecute()
    {
        /*
         * 
         */
        var dnb = new X500DistinguishedNameBuilder();
        dnb.AddCommonName( this.CommonName );

        if ( this.OrganizationalUnitName != null )
            dnb.AddOrganizationalUnitName( this.OrganizationalUnitName );

        if ( this.Country != null )
            dnb.AddCountryOrRegion( this.Country.ToUpperInvariant() );

        if ( this.IsGovEntity == true )
        {
            if ( this.Country == null )
            {
                Console.WriteLine( "err: country is required when requesting gov certificate" );
                return 2;
            }

            dnb.Add( "2.5.4.15", "Gov Entity" );
            dnb.Add( "1.3.6.1.4.1.311.60.2.1.3", this.Country );
        }


        var dn = dnb.Build();
        Console.WriteLine( "with dn: {0}", dn.Name );


        /*
         * Create request
         */
        using var rsa = RSA.Create( this.KeySize );

        var request = new CertificateRequest( dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1 );

        X509KeyUsageFlags kuf = X509KeyUsageFlags.DataEncipherment
                | X509KeyUsageFlags.KeyEncipherment
                | X509KeyUsageFlags.DigitalSignature;

        request.CertificateExtensions.Add( new X509KeyUsageExtension( kuf, false ) );


        /*
         * Create
         */
        var today = DateTime.UtcNow.Date;

        DateTimeOffset notBefore = today;
        DateTimeOffset notAfter = today.AddDays( this.ExpiresInDays );

        var certificate = request.CreateSelfSigned( notBefore, notAfter );


        /*
         * Only on Windows
         */
        if ( RuntimeInformation.IsOSPlatform( OSPlatform.Windows ) )
            certificate.FriendlyName = this.CommonName;


        /*
         * Export
         */
        var bytes = certificate.Export( X509ContentType.Pfx, this.Password );

        File.WriteAllBytes( this.OutputFile, bytes );
        Console.WriteLine( "wrote to {0}...", Path.GetFileName( this.OutputFile ) );

        return 0;
    }
}
