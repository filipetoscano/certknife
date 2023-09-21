using McMaster.Extensions.CommandLineUtils;
using System.Security.Cryptography.X509Certificates;
using Yttrium.Certificate;

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
        var sscr = new SelfSignedCertificateRequest();
        sscr.Name = new DistinguishedName();
        sscr.Name.CommonName = this.CommonName;
        sscr.Name.OrganizationalUnitName = this.OrganizationalUnitName;
        // sscr.DistinguishedName.StateOrProvinceName = this.StateOrProvinceName;
        sscr.Name.Country = this.Country;
        sscr.Name.IsGovEntity = this.IsGovEntity;

        sscr.KeySize = this.KeySize;

        sscr.KeyUsage = X509KeyUsageFlags.DataEncipherment
                | X509KeyUsageFlags.KeyEncipherment
                | X509KeyUsageFlags.DigitalSignature;


        /*
         * 
         */
        X509Certificate2 certificate;

        try
        {
            certificate = X509Utils.GenerateSelfSigned( sscr );
        }
        catch ( InvalidOperationException ex )
        {
            Console.WriteLine( ex.Message );
            return 2;
        }


        /*
         * Export
         */
        var bytes = certificate.Export( X509ContentType.Pfx, this.Password );

        File.WriteAllBytes( this.OutputFile, bytes );
        Console.WriteLine( "wrote to {0}...", Path.GetFileName( this.OutputFile ) );

        return 0;
    }
}
