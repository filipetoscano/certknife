namespace Yttrium.Certificate;

/// <summary />
public abstract class ConverterBase
{
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
