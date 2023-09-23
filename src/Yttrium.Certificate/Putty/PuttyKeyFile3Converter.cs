using Isopoh.Cryptography.Argon2;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysConvert = System.Convert;

namespace Yttrium.Certificate.Putty;

/// <summary />
/// <see href="https://tartarus.org/~simon/putty-snapshots/htmldoc/AppendixC.html" />
public class PuttyKeyFile3Converter : ConverterBase
{
    /// <summary />
    public string Convert( X509Certificate2 certificate,
        string? outputPassword,
        string? comment )
    {
        var rsa = GetRsaParameters( certificate );
        return ToPuttyPrivateKeyFile( rsa, outputPassword ?? "", comment ?? "key" );
    }


    /// <summary />
    public static string ToPuttyPrivateKeyFile( RSAParameters keyParameters, string passphrase, string comment )
    {
        if ( keyParameters.Exponent == null )
            throw new InvalidOperationException( ".Exponent is null" );

        if ( keyParameters.Modulus == null )
            throw new InvalidOperationException( ".Modulus is null" );

        if ( keyParameters.D == null )
            throw new InvalidOperationException( ".D is null" );

        if ( keyParameters.P == null )
            throw new InvalidOperationException( ".P is null" );

        if ( keyParameters.Q == null )
            throw new InvalidOperationException( ".Q is null" );

        if ( keyParameters.InverseQ == null )
            throw new InvalidOperationException( ".InverseQ is null" );


        /*
         * 
         */
        var withPassword = passphrase.Length > 0;


        /*
         * Public key
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
         * Private key
         */
        byte[] privateBuffer = new byte[
            GetPrefixSize( keyParameters.D )
            + keyParameters.D.Length
            + GetPrefixSize( keyParameters.P )
            + keyParameters.P.Length
            + GetPrefixSize( keyParameters.Q )
            + keyParameters.Q.Length
            + GetPrefixSize( keyParameters.InverseQ )
            + keyParameters.InverseQ.Length ];

        using ( var writer = new BinaryWriter( new MemoryStream( privateBuffer ), Encoding.ASCII ) )
        {
            WritePrefixed( writer, keyParameters.D, CheckIfNeedsPadding( keyParameters.D ) );
            WritePrefixed( writer, keyParameters.P, CheckIfNeedsPadding( keyParameters.P ) );
            WritePrefixed( writer, keyParameters.Q, CheckIfNeedsPadding( keyParameters.Q ) );
            WritePrefixed( writer, keyParameters.InverseQ, CheckIfNeedsPadding( keyParameters.InverseQ ) );
        }


        /*
         * 
         */
        string encryptionType = "none";
        int cipherblk = 1;

        if ( withPassword == true )
        {
            encryptionType = "aes256-cbc";
            cipherblk = 16;
        }

        // create the MAC
        int privateEncryptedBufferLength = privateBuffer.Length + cipherblk - 1;
        privateEncryptedBufferLength -= privateEncryptedBufferLength % cipherblk;
        byte[] privateEncryptedBuffer = new byte[ privateEncryptedBufferLength ];
        using ( var writer = new BinaryWriter( new MemoryStream( privateEncryptedBuffer ), Encoding.ASCII ) )
        {
            writer.Write( privateBuffer );

            if ( privateEncryptedBufferLength > privateBuffer.Length )
            {
                Debug.Assert( privateEncryptedBufferLength - privateBuffer.Length < 20 );

                byte[] privateHash = SHA1.HashData( privateBuffer );
                writer.Write( privateHash, 0, privateEncryptedBufferLength - privateBuffer.Length );
            }
        }


        /*
         * 
         */
        byte[] bytesToHash = new byte[ PrefixSize + RsaKeyType.Length + PrefixSize + encryptionType.Length + PrefixSize + comment.Length +
                                      PrefixSize + publicBuffer.Length + PrefixSize + privateEncryptedBuffer.Length ];

        using ( var writer = new BinaryWriter( new MemoryStream( bytesToHash ) ) )
        {
            WritePrefixed( writer, Encoding.ASCII.GetBytes( RsaKeyType ) );
            WritePrefixed( writer, Encoding.ASCII.GetBytes( encryptionType ) );
            WritePrefixed( writer, Encoding.ASCII.GetBytes( comment ) );
            WritePrefixed( writer, publicBuffer );
            WritePrefixed( writer, privateEncryptedBuffer );
        }

        string macKeyStr = "putty-private-key-file-mac-key";
        if ( withPassword == true )
        {
            macKeyStr += passphrase;
        }

        byte[] macKey = SHA1.HashData( Encoding.ASCII.GetBytes( macKeyStr ) );

        string mac;
        using ( var hmacsha1 = new HMACSHA1( macKey ) )
        {
            mac = string.Join( "", hmacsha1.ComputeHash( bytesToHash ).Select( x => string.Format( "{0:x2}", x ) ) );
        }


        /*
         * 
         */
        Argon2Config? argonConfig = null;

        if ( withPassword == true )
        {
            var passwordBytes = Encoding.UTF8.GetBytes( passphrase );

            var saltBytes = new byte[ 16 ];

            var rng = RandomNumberGenerator.Create();
            rng.GetBytes( saltBytes );

            argonConfig = new Argon2Config()
            {
                Type = Argon2Type.DataIndependentAddressing,
                Version = Argon2Version.Nineteen,
                TimeCost = 21, // Argon2-Passes
                MemoryCost = 8192, // Argon2-Memory
                Lanes = 1, // Argon2-Parallelism
                Threads = 1, // Argon2-Parallelism
                Salt = saltBytes,

                Password = passwordBytes,
            };
        }


        /*
         * 
         * 
         */
        var sb = new StringBuilder();
        sb.AppendLine( "PuTTY-User-Key-File-3: " + RsaKeyType );
        sb.AppendLine( "Encryption: " + encryptionType );
        sb.AppendLine( "Comment: " + comment );

        string publicBlob = SysConvert.ToBase64String( publicBuffer );
        var publicLines = SpliceText( publicBlob, PpkLineLength ).ToArray();
        sb.AppendLine( "Public-Lines: " + publicLines.Length );

        foreach ( var line in publicLines )
            sb.AppendLine( line );

        if ( argonConfig != null )
        {
            var argonSalt = SysConvert.ToBase64String( argonConfig.Salt! );

            sb.AppendLine( $"Key-Derivation: Argon2id" );
            sb.AppendLine( $"Argon2-Memory: {argonConfig.MemoryCost}" );
            sb.AppendLine( $"Argon2-Passes: {argonConfig.TimeCost}" );
            sb.AppendLine( $"Argon2-Parallelism: {argonConfig.Lanes}" );
            sb.AppendLine( $"Argon2-Salt: {argonSalt}" );
        }

        string privateBlob = SysConvert.ToBase64String( privateEncryptedBuffer );
        var privateLines = SpliceText( privateBlob, PpkLineLength ).ToArray();
        sb.AppendLine( "Private-Lines: " + privateLines.Length );
        foreach ( var line in privateLines )
            sb.AppendLine( line );

        sb.AppendLine( "Private-MAC: " + mac );

        return sb.ToString();
    }
}
