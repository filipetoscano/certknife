using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;
using Yttrium.Certificate.SSH;

namespace certknife;

/// <summary />
[Command( "ssh", Description = "Converts to SSH public key format" )]
public class ConvertSshCommand
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
    [Option( "-o|--output", CommandOptionType.SingleValue, Description = "Name of output PUB file." )]
    public string OutputFile { get; set; } = "out.pub";

    /// <summary />
    [Option( "--comment", CommandOptionType.SingleValue, Description = "Comment for SSH key line" )]
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
        var conv = new SshPublicKeyConverter();
        var pub = conv.Convert( pfx, comment );


        /*
         * Save
         */
        File.WriteAllText( this.OutputFile, pub );
        Console.WriteLine( "wrote pub to {0}...", Path.GetFileName( this.OutputFile ) );

        return 0;
    }
}
