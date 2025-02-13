// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Logging;
using CoreWCF.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class SecurityTokenReferenceTests
    {
        [Fact]
        public void SecurityTokenReference()
        {
            IdentityModelEventSource.ShowPII = true;
            SamlSecurityTokenHandler samlHandler = new();
            samlHandler.Serializer.DSigSerializer = new CoreWcfDSigSerializer();

#pragma warning disable format
#pragma warning disable SYSLIB0057
            // https://nexus.microsoftonline-p.com/FederationMetadata/2006-12/FederationMetadata.xml
            string cert1 = "MIIC9TCCAd2gAwIBAgIIBhTdvPSIjxkwDQYJKoZIhvcNAQELBQAwKTEnMCUGA1UEAxMeTGl2ZSBJRCBTVFMgU2lnbmluZyBQdWJsaWMgS2V5MB4XDTI0MTIyMzE3MzMzN1oXDTI5MTIyMzE3MzMzN1owKTEnMCUGA1UEAxMeTGl2ZSBJRCBTVFMgU2lnbmluZyBQdWJsaWMgS2V5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0/M1dQHeS1RlBjtup1EFG+LBal/FOAyUPcZz3a0lawchESFl9VcRCq1B3Ar8rqUpu98HVCDP5WYBUlkJmtkSqpHtErFTeU0Qfz+QNCQIHcqijBVWHP3tzLGe9feyT8Xhw42gvOEeTXkHDrKqbI6cSJc0l+fa4blNUxQjStI9K/02ywlw0E3S/fxLfHHJvw2ruikY0iKNq45ZU4jwV1ttk+PvZ5XVSzVp2/Ikc3LJ2ZB91TTDLKRh+JqqKqwZO2l862rC3CWty1cD+x+hLvBnuM+l40UK+wqJQZIOar35rRcqRKGhYG119+cskemLp0bIuWNxLCjeEHFMWCQCrCJsOwIDAQABoyEwHzAdBgNVHQ4EFgQUiYkK/M0AlbDOWitluD0NQwwUGqUwDQYJKoZIhvcNAQELBQADggEBAMyRCv/TmEkO+q8iMSHl0qiOKm0W5hLAs+bIcGScxVVL5pp+31w6pyUzZqZkzJqmpr7Xym3RTPgysRoatHhiVYuB3uufs5VRbd8vjwRMBo6fpAWIPGBDbzv6CXrvH9Ue8TyRQfClAr1BCGWBrXZcbYQich1KJDd2KWANAVEuydPBYLh4gP8pZ0TwPt3kPBq8h0Iv8nmtuONFKpFfJydk27tYJiT5kTMzyUkTWwnN5jJfIdR9nIdsPqnZurl/Jt5MkgY+7+TC76vzzE92ntsJn5Rtznav2gTFmnBL+5HQI2Qz/ki2D3PMDogdUai3kYLVDhQXRQ3B+Gml7XdN1TeaDSo=";
            X509Certificate2 x509Cert1 = new (Convert.FromBase64String(cert1));
            X509SecurityKey x509SecurityKey1 = new(x509Cert1);

            string cert2 = "MIIC9jCCAd6gAwIBAgIJALKuXbAyNbB7MA0GCSqGSIb3DQEBCwUAMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTAeFw0yNTAxMTgxNzA1MDZaFw0zMDAxMTgxNzA1MDZaMCkxJzAlBgNVBAMTHkxpdmUgSUQgU1RTIFNpZ25pbmcgUHVibGljIEtleTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALSCELvRzKrO43vc5+JmdKr5/QmLPPSmaRC9bPvyz7sHu+S/YU5IRVOJhjW2L/bO3gtKWjE98PxCOW3ByRj35Q/RABIxj2utoPD/14L9QJU8q3U6bUkVJ1yvf6v0zgOLXmXutV9Da5jD9lkisKp2VZDlnWYFyjW7DMTBB3CYgsmRo70V79D1+LMsIN5Fh6N43TplXasjby7KcgzVw0Y++Nnol1sydoPODFLuOaSSRLY+7IPIv94PRiWBV5MvSAC44bzcMa7OxNr241RMtnCZzRr9YyyPktJFfZtcH8woM8vZ339ThmUEhVCvQIcm38R4nVOhv5Mvaq1tz7WFJOk6r/ECAwEAAaMhMB8wHQYDVR0OBBYEFFYfac1TdOcQOLSwVU5pJJ13buNCMA0GCSqGSIb3DQEBCwUAA4IBAQB0+mki0ZMFIphP6/b/flwVxP/hlRj0jPTyYO9uUqlPATGOoYRyjfzADyiJPkw2daOeCS6MpLCH+ifvxyBi3LXmDM7jON2cwWabsQ37yuHoIzV0bXVVjN3sHLkkBj1vs4GhldZivNhxZEPIEd1EPOVBNmAWt3bbzsSWOmhd7CT4ZCH+7z5xDUNzcP9mb73+30IiB6QOo/6mfEpW13qh9MZ/qlOqGXJq+Lzk4OFbrt8TKPYh2uepyb9t/BBeR2aTZXCPbYfUIKSgOWc9DsjayRaAGI0UGc/v2kQA7h+Xvx4LF4yfaHqFxUgn9jjZ0JH5Lc85KvzXCjCPoxS1CueijdHs";
            X509Certificate2 x509Cert2 = new (Convert.FromBase64String(cert2));
            X509SecurityKey x509SecurityKey2 = new(x509Cert2);
#pragma warning restore SYSLIB0057
#pragma warning restore format

            X509SubjectKeyIdentifierExtension skiExtension = x509Cert1.Extensions["2.5.29.14"] as X509SubjectKeyIdentifierExtension;

            TokenValidationParameters validationParameters = new()
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                CryptoProviderFactory = new Sha1CryptoProviderFactory()
            };

            List<X509SecurityKey> keys = new() { x509SecurityKey2 };
            x509SecurityKey2.CryptoProviderFactory = new Sha1CryptoProviderFactory();
            validationParameters.IssuerSigningKeys = keys;

            string SubjectKeyIdentifierOid = "2.5.29.14";

            X509ExtensionCollection extensions = x509Cert1.Extensions ?? throw new NotSupportedException("Extensions are null");
            X509SubjectKeyIdentifierExtension x509SubjectKeyIdentifierExtension = extensions[SubjectKeyIdentifierOid] as X509SubjectKeyIdentifierExtension;
            if (x509SubjectKeyIdentifierExtension == null)
                throw new NotSupportedException("X509SubjectKeyIdentifierExtension is null");

            samlHandler.ValidateToken(s_saml1_2_10, validationParameters, out SecurityToken validatedSamlToken);
        }
    }
}
