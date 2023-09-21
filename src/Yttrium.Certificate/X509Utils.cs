using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Yttrium.Certificate;

/// <summary />
public class X509Utils
{
    /// <summary />
    public static X509Certificate2 GenerateSelfSigned( SelfSignedCertificateRequest request )
    {
        /*
         * 
         */
        var dnb = new X500DistinguishedNameBuilder();
        dnb.AddCommonName( request.Name.CommonName );

        if ( request.Name.OrganizationalUnitName != null )
            dnb.AddOrganizationalUnitName( request.Name.OrganizationalUnitName );

        if ( request.Name.Country != null )
            dnb.AddCountryOrRegion( request.Name.Country.ToUpperInvariant() );

        if ( request.Name.IsGovEntity == true )
        {
            if ( request.Name.Country == null )
                throw new InvalidOperationException( "Country is mandatory, is generating gov" );

            dnb.Add( "2.5.4.15", "Gov Entity" );
            dnb.Add( "1.3.6.1.4.1.311.60.2.1.3", request.Name.Country.ToUpperInvariant() );
        }

        var dn = dnb.Build();


        /*
         * Create request
         */
        using var rsa = RSA.Create( request.KeySize );

        var csr = new CertificateRequest( dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1 );

        if ( request.KeyUsage != X509KeyUsageFlags.None )
            csr.CertificateExtensions.Add( new X509KeyUsageExtension( request.KeyUsage, false ) );


        /*
         * Create
         */
        var today = DateTime.UtcNow.Date;

        DateTimeOffset notBefore = today;
        DateTimeOffset notAfter = today.AddDays( request.ExpiresInDays );

        var certificate = csr.CreateSelfSigned( notBefore, notAfter );


        /*
         * Only on Windows
         */
        if ( RuntimeInformation.IsOSPlatform( OSPlatform.Windows ) )
            certificate.FriendlyName = request.Name.CommonName;

        return certificate;
    }
}
