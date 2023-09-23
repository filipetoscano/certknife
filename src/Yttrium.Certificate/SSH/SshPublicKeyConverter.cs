using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysConvert = System.Convert;

namespace Yttrium.Certificate.SSH;

/// <summary />
public class SshPublicKeyConverter : ConverterBase
{
    /// <summary />
    public string Convert( X509Certificate2 certificate, string? comment )
    {
        var keyParameters = GetRsaParameters( certificate );

        if ( keyParameters.Exponent == null )
            throw new InvalidOperationException( ".Exponent is null" );

        if ( keyParameters.Modulus == null )
            throw new InvalidOperationException( ".Modulus is null" );


        /*
         * 
         */
        byte[] publicBuffer = new byte[ 3
            + RsaKeyType.Length
            + GetPrefixSize( keyParameters.Exponent )
            + keyParameters.Exponent.Length
            + GetPrefixSize( keyParameters.Modulus )
            + keyParameters.Modulus.Length + 1 ];

        using ( var writer = new BinaryWriter( new MemoryStream( publicBuffer ), Encoding.ASCII ) )
        {
            writer.Write( new byte[] { 0x00, 0x00, 0x00 } );
            writer.Write( RsaKeyType );
            WritePrefixed( writer, keyParameters.Exponent, CheckIfNeedsPadding( keyParameters.Exponent ) );
            WritePrefixed( writer, keyParameters.Modulus, CheckIfNeedsPadding( keyParameters.Modulus ) );
        }


        /*
         * 
         */
        var sb = new StringBuilder();
        sb.Append( RsaKeyType );
        sb.Append( ' ' );
        sb.Append( SysConvert.ToBase64String( publicBuffer ) );
        sb.Append( ' ' );
        sb.Append( comment ?? "key" );

        return sb.ToString();
    }
}
