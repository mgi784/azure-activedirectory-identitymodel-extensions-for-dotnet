// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;

namespace CoreWCF.IdentityModel.Tokens
{
    /// <summary>
    /// 
    /// </summary>
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
                return new RSASha1SignatureProvider(key, algorithm);
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

        public RSASha1SignatureProvider(SecurityKey key, string algorithm) : base(key, algorithm)
        {
            _key = key as X509SecurityKey;
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

            // TODO: dispose of the hash, use pool
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

    public class CoreWcfDSigSerializer : DSigSerializer
    {
        protected override bool TryReadKeyInfoType(XmlReader reader, ref KeyInfo keyInfo)
        {
            CoreWcfKeyInfo keyInfoType = keyInfo as CoreWcfKeyInfo;
            if (keyInfoType != null)
            {

                if (TryReadSecurityTokenReference(reader, out CoreWcfSecurityTokenReference securityTokenReference))
                {
                    keyInfoType.SecurityTokenReference = securityTokenReference;
                    return true;
                }
                else if (TryReadBinarySecret(reader, out CoreWcfBinarySecret secret))
                {
                    keyInfoType.BinarySecret = secret;
                    return true;
                }
                else if (reader.IsStartElement(CoreWcfXmlSignatureConstants.Elements.EncryptedKey))
                {
                    if (TryReadEncryptedKey(reader, out var encryptedKey))
                        keyInfoType.EncryptedKey = encryptedKey;
                    else
                        return false;
                }
            }

            return base.TryReadKeyInfoType(reader, ref keyInfo);
        }

        private static bool TryReadBinarySecret(XmlReader reader, out CoreWcfBinarySecret secret)
        {
            secret = null;
            if (!reader.IsStartElement("BinarySecret", "http://docs.oasis-open.org/ws-sx/ws-trust/200512"))
                return false;

            secret = new CoreWcfBinarySecret(reader.ReadElementContentAsString());

            return true;
        }

        protected override KeyInfo CreateKeyInfo(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace);

            return new CoreWcfKeyInfo
            {
                Prefix = reader.Prefix
            };
        }

        /// <summary>
        /// Reads the "SecurityTokenReference" element
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned on a <see cref="CoreWcfXmlSignatureConstants.Elements.SecurityTokenReference"/> element.</param>
        /// <param name="securityTokenReference"></param>
        private static bool TryReadSecurityTokenReference(XmlReader reader, out CoreWcfSecurityTokenReference securityTokenReference)
        {
            securityTokenReference = null;
            if (!reader.IsStartElement(CoreWcfXmlSignatureConstants.Elements.SecurityTokenReference, XmlSignatureConstants.SecurityJan2004Namespace))
                return false;

            reader.ReadStartElement(CoreWcfXmlSignatureConstants.Elements.SecurityTokenReference, XmlSignatureConstants.SecurityJan2004Namespace);

            if (!reader.IsStartElement(CoreWcfXmlSignatureConstants.Elements.KeyIdentifier, XmlSignatureConstants.SecurityJan2004Namespace))
                return false;

            string valueType = reader.GetAttribute("ValueType", null);
            string encodingType = reader.GetAttribute("EncodingType", null);
            string value = reader.ReadElementContentAsString(CoreWcfXmlSignatureConstants.Elements.KeyIdentifier, XmlSignatureConstants.SecurityJan2004Namespace);

            reader.ReadEndElement();

            securityTokenReference = new CoreWcfSecurityTokenReference(new CoreWcfSecurityKeyIdentifier(valueType, encodingType, value));

            return true;
        }

        /// <summary>
        /// Attempts to read the <see cref="CoreWcfXmlSignatureConstants.Elements.EncryptedKey"/>
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned on a <see cref="CoreWcfXmlSignatureConstants.Elements.EncryptedKey"/> element.</param>
        /// <param name="encryptedKey">The parsed <see cref="CoreWcfXmlSignatureConstants.Elements.EncryptedKey"/> element.</param>
        protected virtual bool TryReadEncryptedKey(XmlReader reader, out CoreWcfEncryptedKey encryptedKey)
        {
            if (reader == null)
                throw new ArgumentNullException(LogHelper.FormatInvariant("IDX10000: The parameter '{0}' cannot be a 'null' or an empty object. ", nameof(reader)));

            encryptedKey = null;

            if (!reader.IsStartElement(CoreWcfXmlSignatureConstants.Elements.EncryptedKey, XmlSignatureConstants.Namespace))
                return false;

            reader.ReadStartElement(CoreWcfXmlSignatureConstants.Elements.EncryptedKey, XmlSignatureConstants.Namespace);

            if (!reader.IsStartElement(CoreWcfXmlSignatureConstants.Elements.EncryptionMethod, XmlSignatureConstants.Namespace))
                throw XmlUtil.LogReadException(
                    "IDX30011: Unable to read XML. Expecting XmlReader to be at ns.element: '{0}.{1}', found: '{2}.{3}'.",
                    XmlSignatureConstants.Namespace,
                    CoreWcfXmlSignatureConstants.Elements.EncryptionMethod,
                    reader.NamespaceURI,
                    reader.LocalName);

            string algorithm = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm);
            KeyInfo keyInfo = ReadKeyInfo(reader);

            if (!reader.IsStartElement(CoreWcfXmlSignatureConstants.Elements.CipherData, XmlSignatureConstants.Namespace))
                throw XmlUtil.LogReadException(
                    "IDX30011: Unable to read XML. Expecting XmlReader to be at ns.element: '{0}.{1}', found: '{2}.{3}'.",
                    XmlSignatureConstants.Namespace,
                    CoreWcfXmlSignatureConstants.Elements.CipherData,
                    reader.NamespaceURI,
                    reader.LocalName);

            reader.ReadStartElement(CoreWcfXmlSignatureConstants.Elements.CipherData, XmlSignatureConstants.Namespace);

            if (!reader.IsStartElement(CoreWcfXmlSignatureConstants.Elements.CipherValue, XmlSignatureConstants.Namespace))
                throw XmlUtil.LogReadException(
                    "IDX30011: Unable to read XML. Expecting XmlReader to be at ns.element: '{0}.{1}', found: '{2}.{3}'.",
                    XmlSignatureConstants.Namespace,
                    CoreWcfXmlSignatureConstants.Elements.CipherValue,
                    reader.NamespaceURI,
                    reader.LocalName);

            string cipherValue = reader.ReadElementContentAsString(CoreWcfXmlSignatureConstants.Elements.CipherValue, XmlSignatureConstants.Namespace);
            reader.ReadEndElement();
            encryptedKey = new CoreWcfEncryptedKey(algorithm, keyInfo, cipherValue);

            return true;
        }
    }

    /// <summary>
    /// Represents the SecurityTokenReference property of X509Data as per:  https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-X509Data
    /// </summary>
    public class CoreWcfSecurityTokenReference
    {
        /// <summary>
        /// Gets the SecurityKeyIdentifier
        /// </summary>
        public CoreWcfSecurityKeyIdentifier SecurityKeyIdentifier { get; }

        /// <summary>
        /// Creates an IssuerSerial using the specified IssuerName and SerialNumber.
        /// </summary>
        public CoreWcfSecurityTokenReference(CoreWcfSecurityKeyIdentifier securityKeyIdentifier)
        {
            SecurityKeyIdentifier = securityKeyIdentifier;
        }

        /// <summary>
        /// Compares two SecurityTokenReference instances.
        /// </summary>
        /// <param name="securityKey"></param>
        /// <returns></returns>
        public bool MatchesKey(SecurityKey securityKey)
        {
            if (securityKey == null)
                return false;

            if (SecurityKeyIdentifier == null)
                return false;

            if (securityKey is X509SecurityKey x509SecurityKey)
            {
                X509SubjectKeyIdentifierExtension skiExtension = x509SecurityKey.Certificate.Extensions["2.5.29.14"] as X509SubjectKeyIdentifierExtension;
                if (skiExtension == null)
                    return false;

                // TODO: skiExtension.SecurityKeyIdentifier.Value is base64 encoded, skiExtension.RawData is not
                string subjectKeyIdentifier = Convert.ToBase64String(skiExtension.RawData);
                if (SecurityKeyIdentifier.Value == subjectKeyIdentifier)
                    return true;
            }

            return false;
        }
    }

    public class CoreWcfKeyInfo : KeyInfo
    {
        /// <summary>
        ///
        /// </summary>
        public CoreWcfSecurityTokenReference SecurityTokenReference
        {
            get;
            set;
        }

        /// <summary>
        /// Get or sets the 'BinarySecret' value that is a part of 'X509Data'.
        /// </summary>
        public CoreWcfBinarySecret BinarySecret
        {
            get;
            set;
        }

        public CoreWcfEncryptedKey EncryptedKey
        {
            get;
            set;
        }
    }

    /// <summary>
    /// Represents the KeyIdentifier of X509Data as per:  TODO - need url to STRTransform
    /// </summary>
    public class CoreWcfSecurityKeyIdentifier
    {
        /// <summary>
        /// Gets the ValueTupe of the SecurityKeyIdentifier
        /// </summary>
        public string ValueType { get; }

        /// <summary>
        /// Gets the EncodingType of the SecurityKeyIdentifier.
        /// </summary>
        public string EncodingType { get; }

        /// <summary>
        /// Gets the value of the SecurityKeyIdentifier.
        /// </summary>
        public string Value { get; set; }

        /// <summary>
        /// Creates an SecurityKeyIdentifier using the specified KeyIdentifierType and EncodingType.
        /// </summary>
        public CoreWcfSecurityKeyIdentifier(string valueType, string encodingType, string value)
        {
            ValueType = valueType;
            EncodingType = encodingType;
            Value = value;
        }
    }

    public class CoreWcfBinarySecret
    {
        public CoreWcfBinarySecret(string secret)
        {
            Value = secret;
        }

        public string Value { get; }
    }

    /// <summary>
    /// Represents the EncryptedKey Element of X509Data as per:  https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-X509Data
    /// </summary>
    public class CoreWcfEncryptedKey
    {
        /// <summary>
        /// Gets the SecurityKeyIdentifier
        /// </summary>
        public string EncryptionMethod { get; }

        /// <summary>
        /// encryptedKey
        /// </summary>
        public KeyInfo KeyInfo { get; }

        /// <summary>
        ///
        /// </summary>
        public string CipherData { get; }

        /// <summary>
        /// Creates an EncryptedKey 
        /// </summary>
        public CoreWcfEncryptedKey(string encryptionMethod, KeyInfo keyInfo, string cipherData)
        {
            EncryptionMethod = encryptionMethod;
            KeyInfo = keyInfo;
            CipherData = cipherData;
        }
    }

    public static class CoreWcfXmlSignatureConstants
    {
#pragma warning disable 1591

        public static class Attributes
        {
            public const string EncodingType = "EncodingType";
            public const string ValueType = "ValueType";
        }

        public static class Elements
        {
            public const string CipherData = "CipherData";
            public const string CipherValue = "CipherValue";
            public const string DigestMethod = "DigestMethod";
            public const string EncryptedKey = "EncryptedKey";
            public const string EncryptionMethod = "EncryptionMethod";
            public const string KeyIdentifier = "KeyIdentifier";
            public const string SecurityTokenReference = "SecurityTokenReference";
        }
#pragma warning restore 1591
    }

}
