using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace certknife;

/// <summary />
[Command( "cer", Description = "Converts to a PEM encoded .cer file, containing public key only" )]
public class ConvertCerCommand
{
    /// <summary />
    [Argument( 0, Description = "Input PFX file" )]
    [Required]
    [FileExists]
    public string? InputFile { get; set; }

    /// <summary />
    [Option( "--password", CommandOptionType.SingleValue, Description = "Password protecting PFX file." )]
    public string? Password { get; set; }


    /// <summary />
    [Option( "-o|--output", CommandOptionType.SingleValue, Description = "Name of output CER file." )]
    public string OutputFile { get; set; } = "out.cer";


    /// <summary />
    public int OnExecute()
    {
        /*
         * Load
         */
        X509Certificate2 pfx;

        try
        {
            pfx = new X509Certificate2( this.InputFile!, this.Password, X509KeyStorageFlags.Exportable );
        }
        catch ( CryptographicException ex )
        {
            Console.WriteLine( "err: unable to load certificate: {0}", ex.Message );

            return 1;
        }


        /*
         * Convert
         */
        // TODO

        return 0;
    }
}
