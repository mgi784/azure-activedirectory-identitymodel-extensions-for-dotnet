// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents the SecurityTokenReference property of X509Data as per:  https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-X509Data
    /// </summary>
    public class SecurityTokenReference
    {
        /// <summary>
        /// Gets the SecurityKeyIdentifier
        /// </summary>
        public SecurityKeyIdentifier SecurityKeyIdentifier { get; }

        /// <summary>
        /// Creates an IssuerSerial using the specified IssuerName and SerialNumber.
        /// </summary>
        public SecurityTokenReference(SecurityKeyIdentifier securityKeyIdentifier)
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

                string subjectKeyIdentifier = Convert.ToBase64String(skiExtension.RawData);
                if (SecurityKeyIdentifier.Value == subjectKeyIdentifier)
                    return true;
            }

            return false;
        }
    }
}
