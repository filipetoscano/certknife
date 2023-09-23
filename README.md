`certknife`
=========================================================================

Swiss knife for certificate handling, in C#.

```
> certknife --help
Usage: certknife [command] [options]

Options:
  -?|-h|--help  Show help information.

Commands:
  convert       Converts a PFX to another format (see sub-commands)
  create        Creates a new self-signed X509 certificate
  inspect       Inspects a PFX/CER certificate file

Run 'certknife [command] -?|-h|--help' for more information about a command.
```


Testing locally
-------------------------------------------------------------------------

```
dotnet run -- create --common-name="Filipe Toscano"
dotnet run -- inspect out.pfx
dotnet run -- convert ppk out.pfx --ppk=2
dotnet run -- convert ssh out.pfx --console
```
