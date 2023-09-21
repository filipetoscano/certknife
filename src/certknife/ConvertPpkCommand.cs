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
    [Option( "-o|--output", CommandOptionType.SingleValue, Description = "Name of output PPK file." )]
    public string OutputFile { get; set; } = "out.ppk";

    /// <summary />
    [Option( "--comment", CommandOptionType.SingleValue, Description = "Comment for PPK file" )]
    public string? Comment { get; set; }


    /// <summary />
    public int OnExecute()
    {
        /*
         * Load
         */
        var pfx = new X509Certificate2( this.InputFile!, this.Password );


        /*
         * 
         */
        var comment = this.Comment ?? pfx.Subject;


        /*
         * Convert
         */
        var conv = new PuttyKeyFileConverter();
        var ppk = conv.Convert( pfx, this.Password, comment );


        /*
         * Save
         */
        File.WriteAllText( this.OutputFile, ppk );

        return 0;
    }
}
