// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Tokens
{
    public class MldsaSecurityKey : IDisposable
    {
        private bool _disposed;

        public MldsaSecurityKey()
        {
            PublicKey = string.Empty;
            PrivateKey = string.Empty;
            Kid = string.Empty;
        }

        public static MldsaSecurityKey CreateKey(SYMCRYPT_MLDSA_PARAMS_ENUM keyType)
        {
            MldsaSecurityKey key = new MldsaSecurityKey();

            // Initialize the key structure
            key.Handle = SymCrypt.SymCryptMlDsakeyAllocate(SYMCRYPT_MLDSA_PARAMS_ENUM.SYMCRYPT_MLDSA_PARAMS_MLDSA44);

            // Generate the key
            int error = SymCrypt.SymCryptMlDsakeyGenerate(key.Handle, 0);
            long sizeOfKey = 0;

            error = SymCrypt.SymCryptMlDsaSizeofKeyFormatFromParams(
                keyType,
                SYMCRYPT_MLDSAKEY_FORMAT.SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY,
                ref sizeOfKey);

            // TODO stackalloc.
            byte[] keyFormat = new byte[sizeOfKey];

            error = SymCrypt.SymCryptMlDsakeyGetValue(
                key.Handle,
                keyFormat,
                sizeOfKey,
                SYMCRYPT_MLDSAKEY_FORMAT.SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY,
                0);

            key.PrivateKey = Convert.ToBase64String(keyFormat);

            error = SymCrypt.SymCryptMlDsaSizeofKeyFormatFromParams(
                keyType,
                SYMCRYPT_MLDSAKEY_FORMAT.SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
                ref sizeOfKey);

            error = SymCrypt.SymCryptMlDsakeyGetValue(
                key.Handle,
                keyFormat,
                sizeOfKey,
                SYMCRYPT_MLDSAKEY_FORMAT.SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
                0);

            key.PublicKey = Convert.ToBase64String(keyFormat, 0, (int)sizeOfKey);

            int signatureSize = 0;
            error = SymCrypt.SymCryptMlDsaSizeofSignatureFromParams(keyType, ref signatureSize);

            key.SignatureSize = signatureSize;

            return key;
        }

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

        public void HydrateKey(string publicKey)
        {
            byte[] hydratedMldsaKey = Convert.FromBase64String(publicKey);
            int error = SymCrypt.SymCryptMlDsakeySetValue(
                hydratedMldsaKey,
                hydratedMldsaKey.Length,
                SYMCRYPT_MLDSAKEY_FORMAT.SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
                0,
                Handle);
        }

        private int SignatureSize { get; set; }

        public string PublicKey { get; private set; }

        public string PrivateKey { get; private set; }

        public string Kid { get; private set; }

        private IntPtr Handle { get; set; }

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

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}

