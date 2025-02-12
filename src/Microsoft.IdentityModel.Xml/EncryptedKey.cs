// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents the EncryptedKey Element of X509Data as per:  https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-X509Data
    /// </summary>
    public class EncryptedKey
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
        /// Creates an IssuerSerial using the specified IssuerName and SerialNumber.
        /// </summary>
        public EncryptedKey(string encryptionMethod, KeyInfo keyInfo, string cipherData)
        {
            EncryptionMethod = encryptionMethod;
            KeyInfo = keyInfo;
            CipherData = cipherData;
        }
    }
}
