﻿using System.Security.Cryptography.X509Certificates;

namespace Yttrium.Certificate.Putty;

/// <summary />
public class PuttyKeyFile3Converter
{
    /// <summary />
    public string Convert( X509Certificate2 certificate, string? passphrase, string? comment )
    {
        return "PPK TEXT FILE";
    }
}