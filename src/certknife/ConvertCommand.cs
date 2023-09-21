using McMaster.Extensions.CommandLineUtils;
using System.ComponentModel.DataAnnotations;

namespace certknife;

/// <summary />
[Command( "convert", Description = "Converts a PFX to another format (see sub-commands)" )]
[Subcommand( typeof( ConvertCerCommand ) )]
[Subcommand( typeof( ConvertPpkCommand ) )]
[Subcommand( typeof( ConvertSshCommand ) )]
public class ConvertCommand
{
    /// <summary />
    public int OnExecute( CommandLineApplication app )
    {
        app.ShowHelp();
        return 1;
    }
}
