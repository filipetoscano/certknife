using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;
using Yttrium.Certificate.Putty;

namespace certknife;

/// <summary />
[Command( "ppk", Description = "Converts to PPK (putty key file) format" )]
public class ConvertPpkCommand
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
    [Option( "--same", CommandOptionType.NoValue, Description = "When used, PPK password will be same as PFX." )]
    public bool Same { get; set; }


    /// <summary />
    [Option( "-o|--output", CommandOptionType.SingleValue, Description = "Name of output PPK file." )]
    public string OutputFile { get; set; } = "out.ppk";

    /// <summary />
    [Option( "--output-password", CommandOptionType.SingleValue, Description = "Password protecting PPK file." )]
    public string? OutputPassword { get; set; }

    /// <summary />
    [Option( "--ppk", CommandOptionType.SingleValue, Description = "Version of PPK file." )]
    public PpkVersion Version { get; set; } = PpkVersion.Three;

    /// <summary />
    [Option( "--comment", CommandOptionType.SingleValue, Description = "Comment for PPK file" )]
    public string? Comment { get; set; }


    /// <summary />
    public int OnExecute()
    {
        /*
         * Load
         */
        var pfx = new X509Certificate2( this.InputFile!, this.Password, X509KeyStorageFlags.Exportable );


        /*
         * 
         */
        var comment = this.Comment ?? pfx.Subject;


        /*
         * 
         */
        string? outputPassword;

        if ( this.Same == true )
            outputPassword = this.Password;
        else
            outputPassword = this.OutputPassword;


        /*
         * Convert
         */
        string ppk;

        if ( this.Version == PpkVersion.Three )
        {
            var conv = new PuttyKeyFile3Converter();
            ppk = conv.Convert( pfx, outputPassword, outputPassword, comment );
        }
        else if ( this.Version == PpkVersion.Two )
        {
            var conv = new PuttyKeyFile2Converter();
            ppk = conv.Convert( pfx, this.Password, outputPassword, comment );
        }
        else
        {
            Console.Error.WriteLine( "err: ppk version value '{0}' is invalid", this.Version );
            return 1;
        }


        /*
         * Save
         */
        File.WriteAllText( this.OutputFile, ppk );
        Console.WriteLine( "wrote ppk to {0}...", Path.GetFileName( this.OutputFile ) );

        return 0;
    }


    /// <summary />
    public enum PpkVersion
    {
        /// <summary />
        Two = 2,

        /// <summary />
        Three = 3,
    }
}
