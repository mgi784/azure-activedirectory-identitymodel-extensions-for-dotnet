// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents the KeyIdentifier of X509Data as per:  TODO - need url to STRTransform
    /// </summary>
    public class SecurityKeyIdentifier
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
        public SecurityKeyIdentifier(string valueType, string encodingType, string value)
        {
            ValueType = valueType;
            EncodingType = encodingType;
            Value = value;
        }
    }
}
