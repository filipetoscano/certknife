using McMaster.Extensions.CommandLineUtils;

namespace certknife;

/// <summary />
[Command( "certknife" )]
[Subcommand( typeof( ConvertCommand ) )]
[Subcommand( typeof( CreateCommand ) )]
[Subcommand( typeof( InspectCommand ) )]
public class Program
{
    /// <summary />
    public static int Main( string[] args )
    {
        try
        {
            return CommandLineApplication.Execute<Program>( args );
        }
        catch ( Exception ex )
        {
            Console.WriteLine( ex.ToString() );
            return 1;
        }
    }


    /// <summary />
    public int OnExecute( CommandLineApplication app )
    {
        app.ShowHelp();
        return 1;
    }
}