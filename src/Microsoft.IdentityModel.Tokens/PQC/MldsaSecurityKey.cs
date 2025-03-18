// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents a security key that is used for MLDSA. Similar to RsaSecurityKey.
    /// Eventually the plan is for this to derive from AsymmetricSecurityKey.
    /// AsymetricAdapter will need to be expanded so we will have a pool of these types.
    /// </summary>
    internal class MldsaSecurityKey : IDisposable
    {
        private bool _disposed;

        internal MldsaSecurityKey()
        {
            PublicKey = string.Empty;
            PrivateKey = string.Empty;
            Kid = string.Empty;
        }

        /// <summary>
        /// Creates a random ML-DSA key private and public of the specified type.
        /// </summary>
        /// <param name="keyType"></param>
        /// <returns>A <see cref="MldsaSecurityKey"/> that cam be used for signing and verifying.</returns>
        public static MldsaSecurityKey CreateKey(SYMCRYPT_MLDSA_PARAMS_ENUM keyType)
        {
            MldsaSecurityKey key = new MldsaSecurityKey();

            // Initialize the key structure
            key.Handle = SymCrypt.SymCryptMlDsakeyAllocate(keyType);

            // Generate the key
            int error = SymCrypt.SymCryptMlDsakeyGenerate(key.Handle, 0);
            long sizeOfKey = 0;

            error = SymCrypt.SymCryptMlDsaSizeofKeyFormatFromParams(
                keyType,
                SYMCRYPT_MLDSAKEY_FORMAT.PRIVATE_KEY,
                ref sizeOfKey);

            // TODO stackalloc.
            byte[] keyFormat = new byte[sizeOfKey];

            error = SymCrypt.SymCryptMlDsakeyGetValue(
                key.Handle,
                keyFormat,
                sizeOfKey,
                SYMCRYPT_MLDSAKEY_FORMAT.PRIVATE_KEY,
                0);

            key.PrivateKey = Convert.ToBase64String(keyFormat);

            error = SymCrypt.SymCryptMlDsaSizeofKeyFormatFromParams(
                keyType,
                SYMCRYPT_MLDSAKEY_FORMAT.PUBLIC_KEY,
                ref sizeOfKey);

            error = SymCrypt.SymCryptMlDsakeyGetValue(
                key.Handle,
                keyFormat,
                sizeOfKey,
                SYMCRYPT_MLDSAKEY_FORMAT.PUBLIC_KEY,
                0);

            key.PublicKey = Convert.ToBase64String(keyFormat, 0, (int)sizeOfKey);

            int signatureSize = 0;
            error = SymCrypt.SymCryptMlDsaSizeofSignatureFromParams(keyType, ref signatureSize);

            key.SignatureSize = signatureSize;

            return key;
        }

        /// <summary>
        /// Signs a byte array using ML-DSA
        /// </summary>
        /// <param name="data">The data to sign.</param>
        /// <param name="signature">The Signature.</param>
        /// <remarks>This is an inefficient model, as we should not be allocating here.
        /// Eventually we will follow the model of using the ArrayPool for allocations.</remarks>
        public void SignData(byte[] data, out byte[] signature)
        {
            byte[] nullBytes = Array.Empty<byte>();
            long signatureLength = SignatureSize;
            signature = new byte[SignatureSize];
            int error = SymCrypt.SymCryptMlDsaSign(
                Handle,
                data,
                data.Length,
                nullBytes,
                0,
                0,
                signature,
                signatureLength);
        }

        /// <summary>
        /// Verifies a signature using ML-DSA
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signature">The signature that should match.</param>
        /// <returns></returns>
        public bool VerifyData(byte[] data, byte[] signature)
        {
            byte[] nullBytes = Array.Empty<byte>();
            int error = SymCrypt.SymCryptMlDsaVerify(
                Handle,
                data,
                data.Length,
                nullBytes,
                0,
                signature,
                signature.Length,
                0);

            return error == 0;
        }

        /// <summary>
        /// Will hydrate the key from a base64 encoded string.
        /// </summary>
        /// <param name="publicKey">The base64 encoded public key.</param>
        /// <param name="keyType">The type of the key: MLDSA44, MLDSA65, MLDSA87</param>
        /// <remarks>This method is just stubbed out right now.</remarks>
        public static MldsaSecurityKey HydrateKey(string publicKey, SYMCRYPT_MLDSA_PARAMS_ENUM keyType)
        {
            if (keyType != SYMCRYPT_MLDSA_PARAMS_ENUM.MLDSA44)
                throw new NotImplementedException("Only MLDSA44 is supported at this time.");

            byte[] hydratedMldsaKey = Convert.FromBase64String(publicKey);

            return new MldsaSecurityKey();
        }

        /// <summary>
        /// The length of the signature.
        /// </summary>
        private int SignatureSize { get; set; }

        /// <summary>
        /// The public key in Base64 format.
        /// </summary>
        public string PublicKey { get; private set; }

        /// <summary>
        /// The private key in Base64 format.
        /// </summary>
        public string PrivateKey { get; private set; }

        /// <summary>
        /// The key identifier.
        /// </summary>
        public string Kid { get; private set; }

        /// <summary>
        /// The handle to the key returned from SymCrypt.
        /// </summary>
        private IntPtr Handle { get; set; }

        /// <summary>
        /// Disposes of the key that is allocated by the OS, returned by SymCrypt.
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (Handle != IntPtr.Zero)
                {
                    SymCrypt.SymCryptMlDsakeyFree(Handle);
                    Handle = IntPtr.Zero;
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// Disposes of the key that is allocated by the OS, returned by SymCrypt.
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}

