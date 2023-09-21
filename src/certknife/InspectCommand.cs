using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace certknife;

/// <summary />
[Command( "inspect" )]
public class InspectCommand
{
    /// <summary />
    [Argument( 0 )]
    [Required]
    [FileExists]
    public string? InputFile { get; set; }

    /// <summary />
    [Option( "--format", CommandOptionType.SingleValue, Description = "Format of console output" )]
    public OutputFormat? OutputFormat { get; set; }

    /// <summary />
    public int OnExecute()
    {
        /*
         * 
         */
        var cer = new X509Certificate2( this.InputFile! );


        /*
         * 
         */
        var summary = CertificateSummary.From( cer );


        /*
         * 
         */
        if ( this.OutputFormat == certknife.OutputFormat.Json )
        {
            var json = JsonSerializer.Serialize( summary, new JsonSerializerOptions() { WriteIndented = true });

            Console.WriteLine( json );
        }
        else
        {
            Console.WriteLine( "      subject = {0}", summary.Subject );
            Console.WriteLine( "valid from/to = {0} - {1}", summary.NotBefore, summary.NotAfter );
            Console.WriteLine( "  private key = {0}", summary.HasPrivateKey );
            Console.WriteLine( "   thumbprint = {0}", summary.Thumbprint );
        }

        return 0;
    }


    /// <summary />
    public class CertificateSummary
    {
        /// <summary />
        public string Subject { get; set; } = default!;

        /// <summary />
        public DateTime NotAfter { get; set; }

        /// <summary />
        public DateTime NotBefore { get; set; }

        /// <summary />
        public bool HasPrivateKey { get; set; }

        /// <summary />
        public string Thumbprint { get; set; } = default!;


        /// <summary />
        public static CertificateSummary From( X509Certificate2 certificate )
        {
            var cs = new CertificateSummary();
            cs.Subject = certificate.Subject;
            cs.NotBefore = certificate.NotBefore;
            cs.NotAfter = certificate.NotAfter;
            cs.HasPrivateKey = certificate.HasPrivateKey;
            cs.Thumbprint = certificate.Thumbprint.ToLowerInvariant();

            return cs;
        }
    }
}
