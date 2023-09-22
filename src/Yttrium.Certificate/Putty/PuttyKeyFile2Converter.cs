using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SysConvert = System.Convert;

namespace Yttrium.Certificate.Putty;

/// <summary />
/// <see href="https://gist.github.com/bosima/ee6630d30b533c7d7b2743a849e9b9d0" />
public class PuttyKeyFile2Converter
{
    /*
     * Reference: https://gist.github.com/bosima/ee6630d30b533c7d7b2743a849e9b9d0
     * Reference: https://github.com/akira345/pem2ppk, Thanks akira345!
     * Reference: https://antonymale.co.uk/generating-putty-key-files.html, Thanks canton7!
     */

    private const int prefixSize = 4;
    private const int paddedPrefixSize = prefixSize + 1;
    private const int lineLength = 64;
    private const string keyType = "ssh-rsa";


    /// <summary />
    public string Convert( X509Certificate2 certificate,
        string? certificatePassword,
        string? outputPassword,
        string? comment )
    {
        if ( certificate.HasPrivateKey == false )
            throw new InvalidOperationException( "Certificate does not have private key" );


        /*
         * From:
         * https://stackoverflow.com/questions/54483371/cannot-export-rsa-private-key-parameters-the-requested-operation-is-not-support
         */
        var password = certificatePassword ?? "";
        RSAParameters rsa;

        using ( RSA exportRewriter = RSA.Create() )
        {
            // Only one KDF iteration is being used here since it's immediately being
            // imported again.  Use more if you're actually exporting encrypted keys.
            exportRewriter.ImportEncryptedPkcs8PrivateKey(
                password,
                exportRewriter.ExportEncryptedPkcs8PrivateKey(
                    password,
                    new PbeParameters(
                        PbeEncryptionAlgorithm.Aes128Cbc,
                        HashAlgorithmName.SHA256,
                        1 ) ),
                out _ );

            rsa = exportRewriter.ExportParameters( true );
        }

        return RSAToPuttyPrivateKey( rsa, outputPassword ?? "", comment ?? "" );
    }


    /// <summary />
    public static string RSAToPuttyPrivateKey( RSAParameters keyParameters, string passphrase, string comment )
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
         * Public key
         */
        byte[] publicBuffer = new byte[ 3
            + keyType.Length 
            + GetPrefixSize( keyParameters.Exponent ) 
            + keyParameters.Exponent.Length 
            + GetPrefixSize( keyParameters.Modulus ) 
            + keyParameters.Modulus.Length + 1 ];

        using ( var writer = new BinaryWriter( new MemoryStream( publicBuffer ), Encoding.ASCII ) )
        {
            writer.Write( new byte[] { 0x00, 0x00, 0x00 } );
            writer.Write( keyType );
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

        if ( string.IsNullOrWhiteSpace( passphrase ) == false )
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
                using ( var sha1 = SHA1.Create() )
                {
                    byte[] privateHash = sha1.ComputeHash( privateBuffer );
                    writer.Write( privateHash, 0, privateEncryptedBufferLength - privateBuffer.Length );
                }
            }
        }


        /*
         * 
         */
        byte[] bytesToHash = new byte[ prefixSize + keyType.Length + prefixSize + encryptionType.Length + prefixSize + comment.Length +
                                      prefixSize + publicBuffer.Length + prefixSize + privateEncryptedBuffer.Length ];

        using ( var writer = new BinaryWriter( new MemoryStream( bytesToHash ) ) )
        {
            WritePrefixed( writer, Encoding.ASCII.GetBytes( keyType ) );
            WritePrefixed( writer, Encoding.ASCII.GetBytes( encryptionType ) );
            WritePrefixed( writer, Encoding.ASCII.GetBytes( comment ) );
            WritePrefixed( writer, publicBuffer );
            WritePrefixed( writer, privateEncryptedBuffer );
        }

        string macKeyStr = "putty-private-key-file-mac-key";
        if ( !string.IsNullOrWhiteSpace( passphrase ) )
        {
            macKeyStr += passphrase;
        }

        byte[] macKey;
        using ( var sha1 = SHA1.Create() )
        {
            macKey = sha1.ComputeHash( Encoding.ASCII.GetBytes( macKeyStr ) );
        }

        string mac;
        using ( var hmacsha1 = new HMACSHA1( macKey ) )
        {
            mac = string.Join( "", hmacsha1.ComputeHash( bytesToHash ).Select( x => string.Format( "{0:x2}", x ) ) );
        }


        /*
         * 
         */
        if ( !string.IsNullOrWhiteSpace( passphrase ) )
        {
            byte[] passBytes = Encoding.ASCII.GetBytes( passphrase );
            int passBufferLength = passphrase.Length + 4;

            byte[] passBuffer1 = new byte[ passBufferLength ];
            Buffer.BlockCopy( passBytes, 0, passBuffer1, 4, passBytes.Length );
            byte[] passKey1;
            using ( var sha1 = SHA1.Create() )
            {
                passKey1 = sha1.ComputeHash( passBuffer1 );
            }

            byte[] passBuffer2 = new byte[ passBufferLength ];
            passBuffer2[ 3 ] = 1;
            Buffer.BlockCopy( passBytes, 0, passBuffer2, 4, passBytes.Length );
            byte[] passKey2;
            using ( var sha1 = SHA1.Create() )
            {
                passKey2 = sha1.ComputeHash( passBuffer2 );
            }

            byte[] passKey = new byte[ 40 ];
            Buffer.BlockCopy( passKey1, 0, passKey, 0, 20 );
            Buffer.BlockCopy( passKey2, 0, passKey, 20, 20 );

            byte[] iv = new byte[ 16 ];
            byte[] aesKey = new byte[ 32 ];
            Buffer.BlockCopy( passKey, 0, aesKey, 0, 32 );

            privateEncryptedBuffer = AES256Encrypt( aesKey, iv, privateEncryptedBuffer );
        }

        
        /*
         * 
         * 
         */
        var sb = new StringBuilder();
        sb.AppendLine( "PuTTY-User-Key-File-2: " + keyType );
        sb.AppendLine( "Encryption: " + encryptionType );
        sb.AppendLine( "Comment: " + comment );

        string publicBlob = SysConvert.ToBase64String( publicBuffer );
        var publicLines = SpliceText( publicBlob, lineLength ).ToArray();
        sb.AppendLine( "Public-Lines: " + publicLines.Length );
        
        foreach ( var line in publicLines )
            sb.AppendLine( line );

        string privateBlob = SysConvert.ToBase64String( privateEncryptedBuffer );
        var privateLines = SpliceText( privateBlob, lineLength ).ToArray();
        sb.AppendLine( "Private-Lines: " + privateLines.Length );
        foreach ( var line in privateLines )
            sb.AppendLine( line );

        sb.AppendLine( "Private-MAC: " + mac );

        return sb.ToString();
    }


    /// <summary />
    private static void WritePrefixed( BinaryWriter writer, byte[] bytes, bool addLeadingNull = false )
    {
        var length = bytes.Length;
        if ( addLeadingNull )
            length++;

        if ( BitConverter.IsLittleEndian )
        {
            writer.Write( BitConverter.GetBytes( length ).Reverse().ToArray() );
        }
        else
        {
            writer.Write( BitConverter.GetBytes( length ) );
        }
        if ( addLeadingNull )
            writer.Write( (byte) 0x00 );
        writer.Write( bytes );
    }


    /// <summary />
    private static IEnumerable<string> SpliceText( string text, int length )
    {
        for ( int i = 0; i < text.Length; i += length )
        {
            yield return text.Substring( i, Math.Min( length, text.Length - i ) );
        }
    }


    /// <summary />
    private static bool CheckIfNeedsPadding( byte[] bytes )
    {
        // 128 == 10000000
        // This means that the number of bits can be divided by 8.
        // According to the algorithm in putty, you need to add a padding.
        return bytes[ 0 ] >= 128;
    }


    /// <summary />
    private static int GetPrefixSize( byte[] bytes )
    {
        return CheckIfNeedsPadding( bytes ) ? paddedPrefixSize : prefixSize;
    }


    /// <summary />
    private static byte[] AES256Encrypt( byte[] key, byte[] iv, byte[] bytes )
    {
        using ( RijndaelManaged rijalg = new RijndaelManaged() )
        {
            rijalg.BlockSize = 128;
            rijalg.KeySize = 256;
            rijalg.Padding = PaddingMode.None;
            rijalg.Mode = CipherMode.CBC;
            rijalg.Key = key;
            rijalg.IV = iv;

            ICryptoTransform encryptor = rijalg.CreateEncryptor( rijalg.Key, rijalg.IV );
            return encryptor.TransformFinalBlock( bytes, 0, bytes.Length );
        }
    }
}
