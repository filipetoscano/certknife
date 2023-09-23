using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Yttrium.Certificate;

/// <summary />
public abstract class ConverterBase
{
    /// <summary />
    /// <returns>RSA parameters.</returns>
    /// <see href="https://stackoverflow.com/questions/54483371/cannot-export-rsa-private-key-parameters-the-requested-operation-is-not-support" />
    protected static RSAParameters GetRsaParameters( X509Certificate2 certificate )
    {
        if ( certificate.HasPrivateKey == false )
            throw new InvalidOperationException( "Certificate does not have private key" );


        /*
         * 
         */
        var rsa = certificate.GetRSAPrivateKey()!;

        try
        {
            return rsa.ExportParameters( true );
        }
        catch
        {
        }


        /*
         * 
         */
        var password = "password";

        using ( RSA exportRewriter = RSA.Create() )
        {
            // Only one KDF iteration is being used here since it's immediately being
            // imported again.  Use more if you're actually exporting encrypted keys.
            exportRewriter.ImportEncryptedPkcs8PrivateKey(
                password,
                rsa.ExportEncryptedPkcs8PrivateKey(
                    password,
                    new PbeParameters(
                        PbeEncryptionAlgorithm.Aes128Cbc,
                        HashAlgorithmName.SHA256,
                        1 ) ),
                out _ );

            return exportRewriter.ExportParameters( true );
        }
    }


    /// <summary />
    protected static void WritePrefixed( BinaryWriter writer, byte[] bytes, bool addLeadingNull = false )
    {
        var length = bytes.Length;

        if ( addLeadingNull == true )
            length++;

        if ( BitConverter.IsLittleEndian == true )
            writer.Write( BitConverter.GetBytes( length ).Reverse().ToArray() );
        else
            writer.Write( BitConverter.GetBytes( length ) );

        if ( addLeadingNull == true )
            writer.Write( (byte) 0x00 );

        writer.Write( bytes );
    }


    /// <summary />
    protected static bool CheckIfNeedsPadding( byte[] bytes )
    {
        // 128 == 10000000
        // This means that the number of bits can be divided by 8.
        // According to the algorithm in putty, you need to add a padding.
        return bytes[ 0 ] >= 128;
    }


    /// <summary />
    protected const int PpkLineLength = 64;

    /// <summary />
    protected const string RsaKeyType = "ssh-rsa";

    /// <summary />
    protected const int PrefixSize = 4;

    /// <summary />
    protected const int PaddingPrefixSize = PrefixSize + 1;

    /// <summary />
    protected static int GetPrefixSize( byte[] bytes )
    {
        return CheckIfNeedsPadding( bytes ) ? PaddingPrefixSize : PrefixSize;
    }
}
