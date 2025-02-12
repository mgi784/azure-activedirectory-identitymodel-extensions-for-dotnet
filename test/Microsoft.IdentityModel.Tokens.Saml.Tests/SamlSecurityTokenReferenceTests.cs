// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class SecurityTokenReferenceTests
    {
        //static string s_saml1_2_10 = @"
        //    <saml:Assertion MajorVersion=""1"" MinorVersion=""1"" AssertionID=""uuid-39accd5a-e463-4e1c-803f-d5c1732c7800"" Issuer=""urn:federation:MicrosoftOnline"" IssueInstant=""2025-02-06T04:47:27.032Z"" xmlns:saml=""urn:oasis:names:tc:SAML:1.0:assertion"">
        //        <saml:Conditions NotBefore=""2025-02-06T04:47:27.032Z"" NotOnOrAfter=""2025-02-21T04:50:27.027Z"">
        //            <saml:AudienceRestrictionCondition>
        //                <saml:Audience>http://FYDIBOHF25SPDLT.coditeksdf.coditek.net</saml:Audience>
        //            </saml:AudienceRestrictionCondition>
        //        </saml:Conditions>
        //        <saml:AuthenticationStatement AuthenticationMethod=""urn:oasis:names:tc:SAML:1.0:am:password"" AuthenticationInstant=""2025-02-06T04:47:27.032Z"">
        //            <saml:Subject>
        //                <saml:NameIdentifier Format=""http://schemas.xmlsoap.org/claims/upn"">/o3q1rTjLs3v3h1rKR8PD/CR1Gt+0M8oA6qe0OZ/9D0=@MicrosoftOnline.com</saml:NameIdentifier>
        //                <saml:SubjectConfirmation>
        //                    <saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:holder-of-key</saml:ConfirmationMethod>
        //                    <KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#"">
        //                        <trust:BinarySecret xmlns:trust=""http://docs.oasis-open.org/ws-sx/ws-trust/200512"">UTX4nQ06p+Zgme+9aGzNgMXLfrrpzemX</trust:BinarySecret>
        //                    </KeyInfo>
        //                </saml:SubjectConfirmation>
        //            </saml:Subject>
        //        </saml:AuthenticationStatement>
        //        <saml:AttributeStatement>
        //            <saml:Subject>
        //                <saml:NameIdentifier Format=""http://schemas.xmlsoap.org/claims/upn"">/o3q1rTjLs3v3h1rKR8PD/CR1Gt+0M8oA6qe0OZ/9D0=@MicrosoftOnline.com</saml:NameIdentifier>
        //            </saml:Subject>
        //            <saml:Attribute AttributeName=""EmailAddress"" AttributeNamespace=""http://schemas.xmlsoap.org/claims"">
        //                <saml:AttributeValue>op_mbx01@coditeksdf.coditek.net</saml:AttributeValue>
        //            </saml:Attribute>
        //            <saml:Attribute AttributeName=""RequestorDomain"" AttributeNamespace=""http://schemas.microsoft.com/ws/2006/04/identity/claims"">
        //                <saml:AttributeValue>outlook.com</saml:AttributeValue>
        //            </saml:Attribute>
        //            <saml:Attribute AttributeName=""action"" AttributeNamespace=""http://schemas.xmlsoap.org/ws/2006/12/authorization/claims"">
        //                <saml:AttributeValue>MSExchange.MailTips</saml:AttributeValue>
        //            </saml:Attribute>
        //            <saml:Attribute AttributeName=""ThirdPartyRequested"" AttributeNamespace=""http://schemas.microsoft.com/ws/2006/04/identity/claims"">
        //                <saml:AttributeValue>True</saml:AttributeValue>
        //            </saml:Attribute>
        //        </saml:AttributeStatement>
        //        <Signature xmlns=""http://www.w3.org/2000/09/xmldsig#"">
        //            <SignedInfo>
        //                <CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
        //                <SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/>
        //                <Reference URI=""#uuid-39accd5a-e463-4e1c-803f-d5c1732c7800"">
        //                    <Transforms>
        //                        <Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature""/>
        //                        <Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/>
        //                    </Transforms>
        //                    <DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/>
        //                    <DigestValue>WqZ/ciJdnjrOn+9Z7X8bLdMt1Xw=</DigestValue>
        //                </Reference>
        //            </SignedInfo>
        //        <SignatureValue>AC/yDGVAOxK16bvkfvCkhKJ+YvVMB1UswR7AaBlRP5xbUBoyWHOWfB90zRSsZXa6PuqI3n1U0prSRLqcvRGrYCQv6vcx0JmVQCC9xJnXwfsNRQZkr7cYbY4trfjgINtdJTAgihvjzVV+zvuZvwecPsZqTUX/BUj0wl8maObstRAx0tBBCCtHhyk5eMdM0t2ohzYuCsP+mYt1w5uX9EPdwkA5QiGNk5bbj8pGztMWLuyxEb6NCwauKrtJrubRxzlsAQAj4eNqUKclFdMWytFbFs5tkWGDfxiNdyJU62Ja4G6VHvYRjWviTK0JzoGBhpzE6t0GO0C6Lr0s2UY5LLS/dw==</SignatureValue>
        //            <KeyInfo>
        //                <o:SecurityTokenReference xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"">
        //                    <o:KeyIdentifier ValueType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier"" EncodingType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"">Vh9pzVN05xA4tLBVTmkknXdu40I=</o:KeyIdentifier>
        //                </o:SecurityTokenReference>
        //            </KeyInfo>
        //        </Signature>
        //    </saml:Assertion>";

        static string s_saml1_2_10_nospace = @"<saml:Assertion MajorVersion=""1"" MinorVersion=""1"" AssertionID=""uuid-39accd5a-e463-4e1c-803f-d5c1732c7800"" Issuer=""urn:federation:MicrosoftOnline"" IssueInstant=""2025-02-06T04:47:27.032Z"" xmlns:saml=""urn:oasis:names:tc:SAML:1.0:assertion""><saml:Conditions NotBefore=""2025-02-06T04:47:27.032Z"" NotOnOrAfter=""2025-02-21T04:50:27.027Z""><saml:AudienceRestrictionCondition><saml:Audience>http://FYDIBOHF25SPDLT.coditeksdf.coditek.net</saml:Audience></saml:AudienceRestrictionCondition></saml:Conditions><saml:AuthenticationStatement AuthenticationMethod=""urn:oasis:names:tc:SAML:1.0:am:password"" AuthenticationInstant=""2025-02-06T04:47:27.032Z""><saml:Subject><saml:NameIdentifier Format=""http://schemas.xmlsoap.org/claims/upn"">/o3q1rTjLs3v3h1rKR8PD/CR1Gt+0M8oA6qe0OZ/9D0=@MicrosoftOnline.com</saml:NameIdentifier><saml:SubjectConfirmation><saml:ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:holder-of-key</saml:ConfirmationMethod><KeyInfo xmlns=""http://www.w3.org/2000/09/xmldsig#""><trust:BinarySecret xmlns:trust=""http://docs.oasis-open.org/ws-sx/ws-trust/200512"">UTX4nQ06p+Zgme+9aGzNgMXLfrrpzemX</trust:BinarySecret></KeyInfo></saml:SubjectConfirmation></saml:Subject></saml:AuthenticationStatement><saml:AttributeStatement><saml:Subject><saml:NameIdentifier Format=""http://schemas.xmlsoap.org/claims/upn"">/o3q1rTjLs3v3h1rKR8PD/CR1Gt+0M8oA6qe0OZ/9D0=@MicrosoftOnline.com</saml:NameIdentifier></saml:Subject><saml:Attribute AttributeName=""EmailAddress"" AttributeNamespace=""http://schemas.xmlsoap.org/claims""><saml:AttributeValue>op_mbx01@coditeksdf.coditek.net</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=""RequestorDomain"" AttributeNamespace=""http://schemas.microsoft.com/ws/2006/04/identity/claims""><saml:AttributeValue>outlook.com</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=""action"" AttributeNamespace=""http://schemas.xmlsoap.org/ws/2006/12/authorization/claims""><saml:AttributeValue>MSExchange.MailTips</saml:AttributeValue></saml:Attribute><saml:Attribute AttributeName=""ThirdPartyRequested"" AttributeNamespace=""http://schemas.microsoft.com/ws/2006/04/identity/claims""><saml:AttributeValue>True</saml:AttributeValue></saml:Attribute></saml:AttributeStatement><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/><SignatureMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#rsa-sha1""/><Reference URI=""#uuid-39accd5a-e463-4e1c-803f-d5c1732c7800""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature""/><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#""/></Transforms><DigestMethod Algorithm=""http://www.w3.org/2000/09/xmldsig#sha1""/><DigestValue>WqZ/ciJdnjrOn+9Z7X8bLdMt1Xw=</DigestValue></Reference></SignedInfo><SignatureValue>AC/yDGVAOxK16bvkfvCkhKJ+YvVMB1UswR7AaBlRP5xbUBoyWHOWfB90zRSsZXa6PuqI3n1U0prSRLqcvRGrYCQv6vcx0JmVQCC9xJnXwfsNRQZkr7cYbY4trfjgINtdJTAgihvjzVV+zvuZvwecPsZqTUX/BUj0wl8maObstRAx0tBBCCtHhyk5eMdM0t2ohzYuCsP+mYt1w5uX9EPdwkA5QiGNk5bbj8pGztMWLuyxEb6NCwauKrtJrubRxzlsAQAj4eNqUKclFdMWytFbFs5tkWGDfxiNdyJU62Ja4G6VHvYRjWviTK0JzoGBhpzE6t0GO0C6Lr0s2UY5LLS/dw==</SignatureValue><KeyInfo><o:SecurityTokenReference xmlns:o=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd""><o:KeyIdentifier ValueType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier"" EncodingType=""http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"">Vh9pzVN05xA4tLBVTmkknXdu40I=</o:KeyIdentifier></o:SecurityTokenReference></KeyInfo></Signature></saml:Assertion>";

        [Fact]
        public void SecurityTokenReference()
        {
            IdentityModelEventSource.ShowPII = true;
            SamlSecurityTokenHandler samlHandler = new();

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

            samlHandler.ValidateToken(s_saml1_2_10_nospace, validationParameters, out SecurityToken validatedSamlTokenNoSpace);
            samlHandler.ValidateToken(s_saml1_2_10_nospace, validationParameters, out SecurityToken validatedSamlToken);
        }
    }

    public class Sha1CryptoProviderFactory : CryptoProviderFactory
    {
        public Sha1CryptoProviderFactory() : base(new InMemoryCryptoProviderCache(new CryptoProviderCacheOptions(), TaskCreationOptions.None, 50))
        {
        }

        public Sha1CryptoProviderFactory(ICryptoProvider cryptoProvider)
        {
            CustomCryptoProvider = cryptoProvider;
        }

        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            if (algorithm == "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
                return null;
            else
                return base.CreateForSigning(key, algorithm);
        }

        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            X509SecurityKey x509SecurityKey = key as X509SecurityKey;
            if (algorithm == "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
            {
                X509Certificate2 cert = x509SecurityKey.Certificate;
                return new RSASha1SignatureProvider(key, cert, algorithm);
            }
            else
                return base.CreateForVerifying(key, algorithm);
        }

        public override HashAlgorithm CreateHashAlgorithm(string algorithm)
        {
            if (algorithm == "http://www.w3.org/2000/09/xmldsig#sha1")
                return SHA1.Create();

            return base.CreateHashAlgorithm(algorithm);
        }

        public override KeyedHashAlgorithm CreateKeyedHashAlgorithm(byte[] keyBytes, string algorithm)
        {
            return base.CreateKeyedHashAlgorithm(keyBytes, algorithm);
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {

            if (algorithm == "http://www.w3.org/2000/09/xmldsig#sha1")
                return true;
            else if (algorithm == "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
                return true;
            else
                return base.IsSupportedAlgorithm(algorithm);
        }

        public override bool IsSupportedAlgorithm(string algorithm, SecurityKey key)
        {
            if (algorithm == "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
                return true;
            else if (algorithm == "http://www.w3.org/2000/09/xmldsig#sha1")
                return true;
            else
                return base.IsSupportedAlgorithm(algorithm, key);
        }

        public override void ReleaseHashAlgorithm(HashAlgorithm hashAlgorithm)
        {
            hashAlgorithm.Dispose();
        }

        public bool ReleaseHashAlgorithmCalled { get; set; }

        public override void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {
            if (CustomCryptoProvider != null)
                CustomCryptoProvider.Release(signatureProvider);
            else
                signatureProvider.Dispose();
        }
    }

    public class RSASha1SignatureProvider : SignatureProvider
    {
        private X509SecurityKey _key;
        private X509Certificate2 _cert;

        public RSASha1SignatureProvider(SecurityKey key, X509Certificate2 cert, string algorithm) : base(key, algorithm)
        {
            _key = key as X509SecurityKey;
            _cert = cert;
        }

        public override byte[] Sign(byte[] input)
        {
            throw new NotImplementedException();
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            RSA rsa = _key.PublicKey as RSA;
            if (rsa == null)
                return false;

            SHA1 sha1 = SHA1.Create();
            byte[] hash = sha1.ComputeHash(input);
            if (rsa.VerifyHash(hash, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1))
                return true;

            return false;
        }

        protected override void Dispose(bool disposing)
        {
        }
    }
}
